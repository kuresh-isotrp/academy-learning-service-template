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
)
from packages.valory.skills.learning_abci.rounds import (
    APICheckRound,
    DecisionMakingRound,
    Event,
    LearningAbciApp,
    SynchronizedData,
    TxPreparationRound,
)
from packages.valory.contracts.gnosis_safe.contract import (
    GnosisSafeContract,
    SafeOperation,
)
from packages.valory.protocols.contract_api import ContractApiMessage
from packages.valory.skills.transaction_settlement_abci.payload_tools import (hash_payload_to_hex,)

import json


HTTP_OK = 200
ETHER_VALUE = 10**18
GNOSIS_CHAIN_ID = "gnosis"
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
        headers = {
            "accept": "application/json",
            "x-cg-pro-api-key": self.params.coingecko_api_key
        }
        result = yield from self.get_http_response(method="GET",url=self.params.coingecko_price_template,headers=headers)
        self.context.logger.info(f"result Price is {result}")
        if result.status_code == 200:
            data = json.loads(result.body.decode('utf-8'))
            price = data['autonolas']['usd']
        else:
            print("Failed to retrieve data, status code:", result.status_code)
            price = 0
        self.context.logger.info(f"Price is {price}")
        return price

    def get_balance(self):
        """Get balance"""
        # Use the contract api to interact with the ERC20 contract
        # result = yield from self.get_contract_api_response()
        yield
        balance = 1.0
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
        # Using the token price from the previous round, decide whether we should make a transfer or not
        event = Event.TRANSACT.value
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
            payload_data = hash_payload_to_hex(
                safe_tx_hash=tx_hash,
                ether_value=ETHER_VALUE,  # we don't send any eth
                safe_tx_gas=SAFE_GAS,
                to_address=self.params.transfer_target_address,
                data=TX_DATA,
            )
            payload = TxPreparationPayload(
                sender=sender, tx_submitter=None, tx_hash=payload_data
            )

        with self.context.benchmark_tool.measure(self.behaviour_id).consensus():
            yield from self.send_a2a_transaction(payload)
            yield from self.wait_until_round_end()

        self.set_done()

    def get_tx_hash(self):
        """Get the tx hash"""
        """Prepares and returns the safe tx hash for a multisend tx."""
        response_msg = yield from self.get_contract_api_response(
            performative=ContractApiMessage.Performative.GET_STATE,  # type: ignore
            contract_address=self.synchronized_data.safe_contract_address,
            contract_id=str(GnosisSafeContract.contract_id),
            contract_callable="get_raw_safe_transaction_hash",
            to_address=self.params.transfer_target_address,
            value=0,
            data=TX_DATA,
            safe_tx_gas=SAFE_GAS,
            chain_id= GNOSIS_CHAIN_ID,
        )


        if response_msg.performative != ContractApiMessage.Performative.STATE:
            self.context.logger.error(
                "Couldn't get safe tx hash. Expected response performative "  # type: ignore
                f"{ContractApiMessage.Performative.STATE.value}, "  # type: ignore
                f"received {response_msg.performative.value}: {response_msg}."
            )
            return False
        self.context.logger.info(f"Response data is {response_msg}")
        tx_hash = cast(str, response_msg.state.body["tx_hash"])[2:]
        self.context.logger.info(f"Transaction hash is {tx_hash}")
        return tx_hash


class LearningRoundBehaviour(AbstractRoundBehaviour):
    """LearningRoundBehaviour"""

    initial_behaviour_cls = APICheckBehaviour
    abci_app_cls = LearningAbciApp  # type: ignore
    behaviours: Set[Type[BaseBehaviour]] = [  # type: ignore
        APICheckBehaviour,
        DecisionMakingBehaviour,
        TxPreparationBehaviour,
    ]


