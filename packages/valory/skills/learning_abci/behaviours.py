# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2024 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""This package contains round behaviours of LearningAbciApp."""

from abc import ABC
from typing import Generator, Set, Type, cast, Dict,List

from packages.valory.skills.abstract_round_abci.base import AbstractRound
from packages.valory.skills.abstract_round_abci.behaviours import (
    AbstractRoundBehaviour,
    BaseBehaviour,
)
from packages.valory.skills.learning_abci.models import Params, SharedState
from packages.valory.skills.learning_abci.payloads import (
    APICheckPayload,
    FetchAndStoreToIPFSPayload,
    RetriveFromIPFSPayload,
    DecisionMakingPayload,
    TxPreparationPayload,
    MultiTxPreparationPayload,
    
)
from packages.valory.skills.learning_abci.rounds import (
    APICheckRound,
    FetchAndStoreToIPFSRound,
    RetriveFromIPFSRound,
    DecisionMakingRound,
    Event,
    LearningAbciApp,
    SynchronizedData,
    TxPreparationRound,
    MultiTxPreparationRound,
)
from packages.valory.contracts.multisend.contract import (
    MultiSendContract,
    MultiSendOperation,
)
from packages.valory.protocols.contract_api import ContractApiMessage
from hexbytes import HexBytes
from packages.valory.contracts.erc20.contract import ERC20
from packages.valory.contracts.gnosis_safe.contract import (
    GnosisSafeContract,
    SafeOperation,
)
from packages.valory.skills.transaction_settlement_abci.payload_tools import (
    hash_payload_to_hex,
)
import requests
from tempfile import mkdtemp
import multibase
import multicodec
from packages.valory.skills.abstract_round_abci.io_.store import SupportedFiletype
from aea.helpers.cid import to_v1
from dataclasses import asdict, dataclass
from pathlib import Path


HTTP_OK = 200
GNOSIS_CHAIN_ID = "gnosis"
ETHER_VALUE = 10**18
TX_DATA = b"0x"
SAFE_GAS = 0
VALUE_KEY = "value"
TO_ADDRESS_KEY = "to_address"
METADATA_FILENAME = "meatadata.json"
V1_HEX_PREFIX = "f01"


class LearningBaseBehaviour(BaseBehaviour, ABC):  # pylint: disable=too-many-ancestors
    """Base behaviour for the learning_abci skill."""

    @property
    def synchronized_data(self) -> SynchronizedData:
        """Return the synchronized data."""
        return cast(SynchronizedData, super().synchronized_data)

    @property
    def params(self) -> Params:
        """Return the params."""
        return cast(Params, super().params)

    @property
    def local_state(self) -> SharedState:
        """Return the state."""
        return cast(SharedState, self.context.state)
    
    @property
    def metadata_filepath(self) -> str:
        """Get the filepath to the metadata."""
        return str(Path(mkdtemp()) / METADATA_FILENAME)


class APICheckBehaviour(LearningBaseBehaviour):  # pylint: disable=too-many-ancestors
    """APICheckBehaviour"""

    matching_round: Type[AbstractRound] = APICheckRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""

        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            price = yield from self.get_price()
            balance = yield from self.get_balance()
            payload = APICheckPayload(sender=sender, price=price, balance=balance)

        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()

        self.set_done()

    def get_price(self):
        """Get token price from Coingecko"""
        # Interact with Coingecko's API
        # result = yield from self.get_http_response("coingecko.com")
        yield
        price = 1.0
        self.context.logger.info(f"Price is {price}")
        return price

    def get_balance(self):
        """Get balance"""
        # Use the contract api to interact with the ERC20 contract
        # result = yield from self.get_contract_api_response()
        #yield
        #balance = 1.0
        response_msg = yield from self.get_contract_api_response(
            performative=ContractApiMessage.Performative.GET_RAW_TRANSACTION,  # type: ignore
            contract_address=self.params.transfer_contract_token_address,
            contract_id=str(ERC20.contract_id),
            contract_callable="check_balance",
            account=self.synchronized_data.safe_contract_address,
            chain_id=GNOSIS_CHAIN_ID,
        )

        if response_msg.performative != ContractApiMessage.Performative.RAW_TRANSACTION:
            self.context.logger.error(
                f"Could not calculate the balance of the safe: {response_msg}"
            )
            return False

        # fetching wallet balance, token decimal is 18
        wallet_balance = (
            response_msg.raw_transaction.body.get("wallet", None)
        ) / 10**18
        # fetching token balance, token decimal is 8
        balance = (response_msg.raw_transaction.body.get("token", None)) / 10**8

        self.context.logger.info(
            f"Wallet Balance is {wallet_balance}, token balance is {balance}"
        )
        self.context.logger.info(f"Balance is {balance}")
        return balance

class FetchAndStoreToIPFSBehaviour(LearningBaseBehaviour):  # pylint: disable=too-many-ancestors
    """IPFS Send Behaviour"""
    matching_round: Type[AbstractRound] = FetchAndStoreToIPFSRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""

        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            metadata_hash = yield from self._fetch_and_store_to_ipfs()
            payload = FetchAndStoreToIPFSPayload(sender=sender,metadata_hash=metadata_hash)
        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()
        self.set_done()

    def _fetch_and_store_to_ipfs(self):

        """Send large metadata to IPFS."""
        @dataclass
        class MetadataItems:
            id: str
            key: str
            decimal: str
            adoptedDecimal: str
        
        @dataclass
        class MetaData:
            updateds: List[MetadataItems]
        @dataclass
        class Data:
            data: MetaData   

        metadata_subgraph = self.query_subgraph()
        self.context.logger.info(f"metadata for the subgraph : {metadata_subgraph}")
        metadataItems = Data(**metadata_subgraph)
        metadata_hash = yield from self.send_to_ipfs(
            self.metadata_filepath, asdict(metadataItems), filetype=SupportedFiletype.JSON
        )
        self.context.logger.info(f"uploaded metadata, has for metadata: {metadata_hash}")
        if metadata_hash is None:
            return False
        """
            The below code is optional to see the data through ipfs link, 
            for demo purpose keeping this
        """
        v1_file_hash = to_v1(metadata_hash)
        v1_file_bytes = cast(bytes, multibase.decode(v1_file_hash))
        multihash_bytes = multicodec.remove_prefix(v1_file_bytes)
        v1_file_hash_hex = V1_HEX_PREFIX + multihash_bytes.hex()
        ipfs_link = self.params.ipfs_base_end_point + v1_file_hash_hex
        self.context.logger.info(f"ipfs link for data: {ipfs_link}")
        return metadata_hash
    
    def query_subgraph(self):
        """Query a subgraph.
        Args:
            url: the subgraph's URL.
            query: the query to be used.
            key: the key to use in order to access the required data.
        Returns:
            a response dictionary.
        """
        content = {"query": "{ assets(first: 100) { id key decimal adoptedDecimal } }", "operationName": "Subgraphs", "variables": {}}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        url=self.params.subgraph_url
        res = requests.post(url, json=content, headers=headers)
        if res.status_code != 200:
            raise ConnectionError(
                "Something went wrong while trying to communicate with the subgraph "
                f"(Error: {res.status_code})!\n{res.text}"
            )
        body = res.json()
        self.context.logger.info(f"body: {body}")
        if "errors" in body.keys():
            raise ValueError(f"The given query is not correct")
        #resData = yield from self.get_http_response(method="POST", url=subgraph_url, content=content, headers=headers)  
        #self.context.logger.info(f"resData: {resData}")
        return body
    
class RetriveFromIPFSBehaviour(LearningBaseBehaviour):  # pylint: disable=too-many-ancestors
    """IPFS Get Behaviour"""
    matching_round: Type[AbstractRound] = RetriveFromIPFSRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""
        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            metadata = yield from self._retrive_data_from_ipfs()
            self.context.logger.info(f"metadata: {metadata}")
            payload = RetriveFromIPFSPayload(sender=sender)
        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()
        self.set_done()

    def _retrive_data_from_ipfs(self):
        """Get large metadata to IPFS."""   
        metadata_data = yield from self.get_from_ipfs(  # type: ignore
            self.synchronized_data.metadata_hash,
            filetype=SupportedFiletype.JSON,
        ) 
        return metadata_data
    
class DecisionMakingBehaviour(
    LearningBaseBehaviour
):  # pylint: disable=too-many-ancestors
    """DecisionMakingBehaviour"""

    matching_round: Type[AbstractRound] = DecisionMakingRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""

        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            event = self.get_event()
            payload = DecisionMakingPayload(sender=sender, event=event)

        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()

        self.set_done()

    def get_event(self):
        """Get the next event"""
        # Using the token balance from the previous round, decide whether we should make a transfer or not
        # using some dummy decision making condition to go for TxPreparation/MultiTxPreparation
        if self.synchronized_data.balance <= 0:
            event = Event.TRANSACT.value
            self.context.logger.info(f"Threshold not reached, moving to {event}")

        elif self.synchronized_data.balance > 0 and self.synchronized_data.balance < 100:
            event = Event.TRANSACT.value
            self.context.logger.info(f"Threshold not reached, moving to {event}")
        else:
            event = Event.MULTI_TRANSACT.value
            self.context.logger.info(f"Threshold reached, moving to {event}")

        self.context.logger.info(f"Event is {event}")
        return event

class TxPreparationBehaviour(
    LearningBaseBehaviour
):  # pylint: disable=too-many-ancestors
    """TxPreparationBehaviour"""

    matching_round: Type[AbstractRound] = TxPreparationRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""

        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            tx_hash = yield from self.get_tx_hash()
            payload = TxPreparationPayload(
                sender=sender, tx_submitter=None, tx_hash=tx_hash
            )

        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()

        self.set_done()

    def get_tx_hash(self):
        """Get the tx hash"""
        # We need to prepare a 1 wei transfer from the safe to another (configurable) account.
        yield
        tx_hash = None
        self.context.logger.info(f"Transaction hash is {tx_hash}")
        return tx_hash
    

class MultiTxPreparationBehaviour(
    LearningBaseBehaviour
):  # pylint: disable=too-many-ancestors
    """MultiTxPreparationBehaviour"""

    matching_round: Type[AbstractRound] = MultiTxPreparationRound

    def async_act(self) -> Generator:
        """Do the act, supporting asynchronous execution."""

        with self.context.benchmark_tool.measure(self.behaviour_id).local():
            sender = self.context.agent_address
            self.context.logger.info(f"Entering into MultiTxPreparationBehaviour")
            # Build the multi_send_txs
            multi_send_txs = []
            #Prepare the native transcation details
            native_tx_details = yield from self.prepare_native_transfer_tx_details()
            multi_send_txs.append(native_tx_details)
            #Prepare the token transcation details
            token_transfer_data = yield from self.prepare_token_transfer_tx_details()
            multi_send_txs.append(token_transfer_data)
            #Get the tx data from multi_send_txs
            contract_api_msg = yield from self.get_contract_api_response(
                performative=ContractApiMessage.Performative.GET_RAW_TRANSACTION,  # type: ignore
                contract_address=self.params.multi_send_contract_token_address,
                contract_id=str(MultiSendContract.contract_id),
                contract_callable="get_tx_data",
                multi_send_txs=multi_send_txs,
                chain_id=GNOSIS_CHAIN_ID
            )
            multi_send_data = cast(str, contract_api_msg.raw_transaction.body["data"])
            multi_send_data = multi_send_data[2:]
            self.context.logger.info(f"multi send data details: {multi_send_data}")
            contract_api_msg = yield from self.get_contract_api_response(
                performative=ContractApiMessage.Performative.GET_STATE,  # type: ignore
                contract_address=self.synchronized_data.safe_contract_address,
                contract_id=str(GnosisSafeContract.contract_id),
                contract_callable="get_raw_safe_transaction_hash",
                to_address=self.params.transfer_target_address,
                value=0,#sum(tx["value"] for tx in multi_send_txs),
                data=bytes.fromhex(multi_send_data),
                operation=SafeOperation.DELEGATE_CALL.value,
                safe_tx_gas=SAFE_GAS,
                chain_id=GNOSIS_CHAIN_ID,
                safe_nonce=0
            )
            self.context.logger.info(f"Multisend data preparation: {contract_api_msg}")
            if contract_api_msg.performative != ContractApiMessage.Performative.STATE:
                self.context.logger.error(
                    f"Could not get Multisend Gnosis Safe tx hash. "
                    f"Expected: {ContractApiMessage.Performative.STATE.value}, "
                    f"Actual: {contract_api_msg.performative.value}"
                )
                return None

            safe_tx_hash = cast(str, contract_api_msg.state.body["tx_hash"])
            safe_tx_hash = safe_tx_hash[2:]
            self.context.logger.info(f"Hash of the Safe transaction: {safe_tx_hash}")

            tx_hash_payload = hash_payload_to_hex(
                safe_tx_hash=safe_tx_hash,
                ether_value=sum(tx["value"] for tx in multi_send_txs),
                safe_tx_gas=SAFE_GAS,
                to_address=self.params.transfer_target_address,
                data=bytes.fromhex(multi_send_data),
                operation=SafeOperation.DELEGATE_CALL.value,
            )
            self.context.logger.info(f"Final tx payload is: {tx_hash_payload}")
            payload = MultiTxPreparationPayload(
                sender=sender,tx_submitter=None, tx_hash=tx_hash_payload
            )
        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()

        self.set_done()
    
    def prepare_native_transfer_tx_details(self):
        """Prepare tx data"""
        self.context.logger.info(f"Inside of prepare_native_transfer_tx_data function {self.synchronized_data.safe_contract_address}")

        # We need to prepare a 10**18 wei transfer from the safe to another (configurable) account.
        response_msg = yield from self.get_contract_api_response(
            performative=ContractApiMessage.Performative.GET_RAW_TRANSACTION,  # type: ignore
            contract_address=self.synchronized_data.safe_contract_address,
            contract_id=str(GnosisSafeContract.contract_id),
            contract_callable="get_raw_safe_transaction_hash",
            to_address=self.params.transfer_target_address,
            value=ETHER_VALUE,
            data=TX_DATA,
            safe_tx_gas=SAFE_GAS,
            chain_id=GNOSIS_CHAIN_ID,
        )
        if response_msg.performative != ContractApiMessage.Performative.RAW_TRANSACTION:
            self.context.logger.error(
                f"Could not get native transfer hash. "
                f"Expected: {ContractApiMessage.Performative.RAW_TRANSACTION.value}, "
                f"Actual: {response_msg.performative.value}"
            )
            return None
        self.context.logger.info(f"native transfer response msg is {response_msg}")
        tx_hash_data = cast(str, response_msg.raw_transaction.body["tx_hash"])
        return {
            "operation": MultiSendOperation.CALL,
            "to":self.params.transfer_target_address,
            "value": ETHER_VALUE,
            "data": tx_hash_data,
        }

    def prepare_token_transfer_tx_details(self):
        """Prepare the tx data"""
        self.context.logger.info(f"Inside of prepare_token_transfer_tx_details function call")
        # We need to prepare a one token transfer from the safe to another (configurable) account.
        response_msg = yield from self.get_contract_api_response(
            performative=ContractApiMessage.Performative.GET_RAW_TRANSACTION,  # type: ignore
            contract_address=self.params.transfer_contract_token_address,
            contract_id=str(ERC20.contract_id),
            contract_callable="build_transfer_tx",
            receiver=self.params.transfer_target_address, 
            amount=10**8,
        )

        if response_msg.performative != ContractApiMessage.Performative.RAW_TRANSACTION:
            self.context.logger.error(
                f"Could not get token transfer hash. "
                f"Expected: {ContractApiMessage.Performative.RAW_TRANSACTION.value}, "
                f"Actual: {response_msg.performative.value}"
            )
            return None

        tx_hash_data = HexBytes(
            cast(bytes, response_msg.raw_transaction.body["data"]).hex()
        )
        return {
            "operation": MultiSendOperation.CALL,
            "to": self.params.transfer_contract_token_address,
            "value": 0,
            "data": tx_hash_data,
            "chain_id":GNOSIS_CHAIN_ID
        }


class LearningRoundBehaviour(AbstractRoundBehaviour):
    """LearningRoundBehaviour"""

    initial_behaviour_cls = APICheckBehaviour
    abci_app_cls = LearningAbciApp  # type: ignore
    behaviours: Set[Type[BaseBehaviour]] = [  # type: ignore
        APICheckBehaviour,
        FetchAndStoreToIPFSBehaviour,
        RetriveFromIPFSBehaviour,
        DecisionMakingBehaviour,
        TxPreparationBehaviour,
        MultiTxPreparationBehaviour,
    ]
