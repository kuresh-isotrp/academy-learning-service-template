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
from typing import Generator, Set, Type, cast

from packages.valory.skills.abstract_round_abci.base import AbstractRound
from packages.valory.skills.abstract_round_abci.behaviours import (
    AbstractRoundBehaviour,
    BaseBehaviour,
)
from packages.valory.skills.learning_abci.models import Params, SharedState
from packages.valory.skills.learning_abci.payloads import (
    APICheckPayload,
    DecisionMakingPayload,
    TxPreparationPayload,
    MultiTxPreparationPayload
    
)
from packages.valory.skills.learning_abci.rounds import (
    APICheckRound,
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


HTTP_OK = 200
GNOSIS_CHAIN_ID = "gnosis"
ETHER_VALUE = 10**18
TX_DATA = b"0x"
SAFE_GAS = 0
VALUE_KEY = "value"
TO_ADDRESS_KEY = "to_address"


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
        if self.synchronized_data.balance < 10:
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
                safe_nonce=9
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
        """Get the tx data"""
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
        #self.context.logger.info(f"Iresponse_msg {response_msg}")
        if response_msg.performative != ContractApiMessage.Performative.RAW_TRANSACTION:
            self.context.logger.error(
                f"Could not get native transfer hash. "
                f"Expected: {ContractApiMessage.Performative.RAW_TRANSACTION.value}, "
                f"Actual: {response_msg.performative.value}"
            )
            return None

        self.context.logger.info(f"Native transfer response msg is {response_msg}")

        tx_hash_data = cast(str, response_msg.raw_transaction.body["tx_hash"])
        #self.context.logger.info(f"Transaction hash data is {tx_hash_data}")
        return {
            "operation": MultiSendOperation.CALL,
            "to":self.params.transfer_target_address,
            "value": ETHER_VALUE,
            "data": tx_hash_data,
        }

    def prepare_token_transfer_tx_details(self):
        """Get the tx data"""
        self.context.logger.info(f"Inside function call: Token transfer")

        # We need to prepare a one token transfer from the safe to another (configurable) account.
        response_msg = yield from self.get_contract_api_response(
            performative=ContractApiMessage.Performative.GET_RAW_TRANSACTION,  # type: ignore
            contract_address="0xcE11e14225575945b8E6Dc0D4F2dD4C570f79d9f",#self.params.transfer_contract_token_address, #"0xcE11e14225575945b8E6Dc0D4F2dD4C570f79d9f",
            contract_id=str(ERC20.contract_id),
            contract_callable="build_transfer_tx",
            receiver=self.params.transfer_target_address,#"0x0889BAEf5367e43FeC10bE1dCE15Da69c562b70E", 
            amount=10**8,
        )

        #self.context.logger.info(f"Token transfer response msg is {response_msg}")

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
            "to": "0xcE11e14225575945b8E6Dc0D4F2dD4C570f79d9f",#self.params.transfer_contract_token_address, #"0xcE11e14225575945b8E6Dc0D4F2dD4C570f79d9f",
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
        DecisionMakingBehaviour,
        TxPreparationBehaviour,
        MultiTxPreparationBehaviour,
    ]
