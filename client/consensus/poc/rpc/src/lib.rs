// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
// Copyright (C) 2021 Subpace Labs, Inc.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! RPC api for PoC.

// TODO: Import these 3 from `sc_consensus_poc` instead
/// Information about new slot that just arrived
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSlotInfo {
	/// Slot number
	pub slot_number: Slot,
	/// Slot challenge
	pub challenge: [u8; 8],
	/// Acceptable solution range
	pub solution_range: u64,
}
/// A function that can be called whenever it is necessary to create a subscription for new slots
pub type NewSlotNotifier = std::sync::Arc<Box<dyn (Fn() -> std::sync::mpsc::Receiver<
	(NewSlotInfo, std::sync::mpsc::SyncSender<Option<Solution>>)
>) + Send + Sync>>;
#[derive(Clone)]
pub struct Solution {
	pub public_key: FarmerId,
	pub nonce: u64,
	pub encoding: Vec<u8>,
	pub signature: Vec<u8>,
	pub tag: [u8; 8],
}

//use sc_consensus_poc::{NewSlotNotifier, NewSlotInfo};
use futures::{FutureExt as _, TryFutureExt as _, SinkExt, TryStreamExt, StreamExt};
use jsonrpc_core::{
	Error as RpcError,
	futures::future as rpc_future,
	Result as RpcResult,
	futures::{
		Future,
		Sink,
		Stream,
		future::Future as Future01,
		future::Executor as Executor01,
	},
};
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed::Subscriber, SubscriptionId, manager::SubscriptionManager};
use sp_consensus_poc::FarmerId;
use serde::{Deserialize, Serialize};
use sp_core::crypto::Public;
use std::{collections::HashMap, sync::Arc};
use log::{debug, warn};
use std::sync::mpsc;
use parking_lot::Mutex;
use futures::channel::mpsc::UnboundedSender;
use futures::future;
use futures::future::Either;
use std::time::Duration;

const SOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

type Slot = u64;
type FutureResult<T> = Box<dyn rpc_future::Future<Item = T, Error = RpcError> + Send>;

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcSolution {
	pub public_key: [u8; 32],
	pub nonce: u64,
	pub encoding: Vec<u8>,
	pub signature: Vec<u8>,
	pub tag: [u8; 8],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProposedProofOfSpaceResult {
	slot_number: Slot,
	solution: Option<RpcSolution>,
}

/// Provides rpc methods for interacting with PoC.
#[rpc]
pub trait PoCApi {
	/// RPC metadata
	type Metadata;

	#[rpc(name = "poc_proposeProofOfSpace")]
	fn propose_proof_of_space(&self, proposed_proof_of_space_result: ProposedProofOfSpaceResult) -> FutureResult<()>;


	/// Slot info subscription
	#[pubsub(subscription = "poc_slot_info", subscribe, name = "poc_subscribeSlotInfo")]
	fn subscribe_slot_info(&self, metadata: Self::Metadata, subscriber: Subscriber<NewSlotInfo>);

	/// Unsubscribe from slot info subscription.
	#[pubsub(subscription = "poc_slot_info", unsubscribe, name = "poc_unsubscribeSlotInfo")]
	fn unsubscribe_slot_info(
		&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId,
	) -> RpcResult<bool>;
}

/// Implements the PoCRpc trait for interacting with PoC.
pub struct PoCRpcHandler {
	manager: SubscriptionManager,
	notification_senders: Arc<Mutex<Vec<UnboundedSender<NewSlotInfo>>>>,
	solution_senders: Arc<Mutex<HashMap<Slot, futures::channel::mpsc::Sender<Option<RpcSolution>>>>>,
}

// TODO: Add more detailed documentation
impl PoCRpcHandler {
	/// Creates a new instance of the PoCRpc handler.
	pub fn new<E>(
		executor: E,
		new_slot_notifier: NewSlotNotifier,
	) -> Self
		where
			E: Executor01<Box<dyn Future01<Item = (), Error = ()> + Send>> + Send + Sync + 'static,
	{
		let notification_senders: Arc<Mutex<Vec<UnboundedSender<NewSlotInfo>>>> = Arc::default();
		let solution_senders: Arc<Mutex<HashMap<Slot, futures::channel::mpsc::Sender<Option<RpcSolution>>>>> = Arc::default();
		std::thread::Builder::new()
			.name("poc_rpc_nsn_handler".to_string())
			.spawn({
				let notification_senders = Arc::clone(&notification_senders);
				let solution_senders = Arc::clone(&solution_senders);
				let new_slot_notifier: std::sync::mpsc::Receiver<
					(NewSlotInfo, mpsc::SyncSender<Option<Solution>>)
				> = new_slot_notifier();

				move || {
					while let Ok((new_slot_info, sync_solution_sender)) = new_slot_notifier.recv() {
						futures::executor::block_on(async {
							let (solution_sender, mut solution_receiver) = futures::channel::mpsc::channel(0);
							solution_senders.lock().insert(new_slot_info.slot_number, solution_sender);
							let mut expected_solutions_count;
							{
								let mut notification_senders = notification_senders.lock();
								expected_solutions_count = notification_senders.len();
								if expected_solutions_count == 0 {
									let _ = sync_solution_sender.send(None);
									return;
								}
								for notification_sender in notification_senders.iter_mut() {
									if notification_sender.send(new_slot_info.clone()).await.is_err() {
										expected_solutions_count -= 1;
									}
								}
							}

							let timeout = futures_timer::Delay::new(SOLUTION_TIMEOUT).map(|_| None);
							let solution = async move {
								// TODO: This doesn't track what client sent a solution, allowing
								//  some clients to send multiple
								let mut potential_solutions_left = expected_solutions_count;
								while let Some(solution) = solution_receiver.next().await {
									if let Some(solution) = solution {
										return Some(Solution {
											public_key: FarmerId::from_slice(&solution.public_key),
											nonce: solution.nonce,
											encoding: solution.encoding,
											signature: solution.signature,
											tag: solution.tag,
										});
									}
									potential_solutions_left -= 1;
									if potential_solutions_left == 0 {
										break;
									}
								}

								return None;
							};

							let solution = match future::select(timeout, Box::pin(solution)).await {
								Either::Left((value1, _)) => value1,
								Either::Right((value2, _)) => value2,
							};

							if let Err(error) = sync_solution_sender.send(solution) {
								debug!("Failed to send solution: {}", error);
							}

							solution_senders.lock().remove(&new_slot_info.slot_number);
						});
					}
				}
			})
			.expect("Failed to spawn poc rpc new slot notifier handler");
		let manager = SubscriptionManager::new(Arc::new(executor));
		Self {
			manager,
			notification_senders,
			solution_senders,
		}
	}
}

impl PoCApi for PoCRpcHandler {
	type Metadata = sc_rpc_api::Metadata;

	fn propose_proof_of_space(&self, proposed_proof_of_space_result: ProposedProofOfSpaceResult) -> FutureResult<()> {
		let sender = self.solution_senders.lock().get(&proposed_proof_of_space_result.slot_number).cloned();
		let future = async move {
			if let Some(mut sender) = sender {
				let _ = sender.send(proposed_proof_of_space_result.solution).await;
			}

			Ok(())
		}.boxed();
		Box::new(future.compat())
	}

	fn subscribe_slot_info(&self, _metadata: Self::Metadata, subscriber: Subscriber<NewSlotInfo>) {
		self.manager.add(subscriber, |sink| {
			let (tx, rx) = futures::channel::mpsc::unbounded();
			self.notification_senders.lock().push(tx);
			sink
				.sink_map_err(|e| warn!("Error sending notifications: {:?}", e))
				.send_all(rx.map(Ok::<_, ()>).compat().map(|res| Ok(res)))
				.map(|_| ())
		});
	}

	fn unsubscribe_slot_info(&self, _metadata: Option<Self::Metadata>, id: SubscriptionId) -> RpcResult<bool> {
		Ok(self.manager.cancel(id))
	}
}
