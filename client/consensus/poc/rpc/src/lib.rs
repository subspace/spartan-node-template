// This file is part of Substrate.

// Copyright (C) 2020-2021 Parity Technologies (UK) Ltd.
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

//! RPC api for babe.

use sc_consensus_babe::{SlotNumber, NewSlotNotifier, NewSlotInfo};
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
use sp_consensus_babe::AuthorityId;
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

type FutureResult<T> = Box<dyn rpc_future::Future<Item = T, Error = RpcError> + Send>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Solution {
	pub public_key: [u8; 32],
	pub nonce: u64,
	pub encoding: Vec<u8>,
	pub signature: Vec<u8>,
	pub tag: [u8; 8],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProposedProofOfSpaceResult {
	slot_number: SlotNumber,
	solution: Option<Solution>,
}

/// Provides rpc methods for interacting with Babe.
#[rpc]
pub trait BabeApi {
	/// RPC metadata
	type Metadata;

	#[rpc(name = "babe_proposeProofOfSpace")]
	fn propose_proof_of_space(&self, proposed_proof_of_space_result: ProposedProofOfSpaceResult) -> FutureResult<()>;


	/// Slot info subscription
	#[pubsub(subscription = "babe_slot_info", subscribe, name = "babe_subscribeSlotInfo")]
	fn subscribe_slot_info(&self, metadata: Self::Metadata, subscriber: Subscriber<NewSlotInfo>);

	/// Unsubscribe from slot info subscription.
	#[pubsub(subscription = "babe_slot_info", unsubscribe, name = "babe_unsubscribeSlotInfo")]
	fn unsubscribe_slot_info(
		&self,
		metadata: Option<Self::Metadata>,
		id: SubscriptionId,
	) -> RpcResult<bool>;
}

/// Implements the BabeRpc trait for interacting with Babe.
pub struct BabeRpcHandler {
	manager: SubscriptionManager,
	notification_senders: Arc<Mutex<Vec<UnboundedSender<NewSlotInfo>>>>,
	solution_senders: Arc<Mutex<HashMap<SlotNumber, futures::channel::mpsc::Sender<Option<Solution>>>>>,
}

impl BabeRpcHandler {
	/// Creates a new instance of the BabeRpc handler.
	pub fn new<E>(
		executor: E,
		new_slot_notifier: NewSlotNotifier,
	) -> Self
		where
			E: Executor01<Box<dyn Future01<Item = (), Error = ()> + Send>> + Send + Sync + 'static,
	{
		let notification_senders: Arc<Mutex<Vec<UnboundedSender<NewSlotInfo>>>> = Arc::default();
		let solution_senders: Arc<Mutex<HashMap<SlotNumber, futures::channel::mpsc::Sender<Option<Solution>>>>> = Arc::default();
		std::thread::Builder::new()
			.name("babe_rpc_nsn_handler".to_string())
			.spawn({
				let notification_senders = Arc::clone(&notification_senders);
				let solution_senders = Arc::clone(&solution_senders);
				let new_slot_notifier: std::sync::mpsc::Receiver<
					(NewSlotInfo, mpsc::SyncSender<Option<sp_consensus_babe::digests::Solution>>)
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
										return Some(sp_consensus_babe::digests::Solution {
											public_key: AuthorityId::from_slice(&solution.public_key),
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
			.expect("Failed to spawn babe rpc new slot notifier handler");
		let manager = SubscriptionManager::new(Arc::new(executor));
		Self {
			manager,
			notification_senders,
			solution_senders,
		}
	}
}

impl BabeApi for BabeRpcHandler {
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

#[cfg(test)]
mod tests {
	use super::*;
	use substrate_test_runtime_client::{
		runtime::Block,
		Backend,
		DefaultTestClientBuilderExt,
		TestClient,
		TestClientBuilderExt,
		TestClientBuilder,
	};
	use sp_application_crypto::AppPair;
	use sp_keyring::Ed25519Keyring;
	use sc_keystore::Store;

	use std::sync::Arc;
	use sc_consensus_babe::{Config, block_import, AuthorityPair};
	use jsonrpc_core::IoHandler;

	/// creates keystore backed by a temp file
	fn create_temp_keystore<P: AppPair>(authority: Ed25519Keyring) -> (KeyStorePtr, tempfile::TempDir) {
		let keystore_path = tempfile::tempdir().expect("Creates keystore path");
		let keystore = Store::open(keystore_path.path(), None).expect("Creates keystore");
		keystore.write().insert_ephemeral_from_seed::<P>(&authority.to_seed())
			.expect("Creates authority key");

		(keystore, keystore_path)
	}

	fn test_babe_rpc_handler(
		deny_unsafe: DenyUnsafe
	) -> BabeRpcHandler<Block, TestClient, sc_consensus::LongestChain<Backend, Block>> {
		let builder = TestClientBuilder::new();
		let (client, longest_chain) = builder.build_with_longest_chain();
		let client = Arc::new(client);
		let config = Config::get_or_compute(&*client).expect("config available");
		let (_, link) = block_import(
			config.clone(),
			client.clone(),
			client.clone(),
		).expect("can initialize block-import");

		let epoch_changes = link.epoch_changes().clone();
		let keystore = create_temp_keystore::<AuthorityPair>(Ed25519Keyring::Alice).0;

		BabeRpcHandler::new(
			client.clone(),
			epoch_changes,
			keystore,
			config,
			longest_chain,
			deny_unsafe,
		)
	}
}
