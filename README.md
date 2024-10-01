## Learning Demo Service

A service which perform the below operations on each state
- API Check to get the Balance of Wallet
- Fetch and store the subgraph data into IPFS, In this service we are using Omen xDai subgraph for fetch data(https://gateway.thegraph.com/api/{api_key}/subgraphs/id/9fUVQpFwzpdWS9bq5WkAnmKbNNcoBwatMR4yZq81pbbz)
- Retrive the IPFS for data validation
- Decession making for Single Tx preparation / Multi Tx preparation Based on Balance
- If Balance is more then the threashhold defined then preparaing Multi Tx for Native and a token
- Genearate hash for the same and submit for Transcation

## System requirements

- Python `>=3.10`
- [Tendermint](https://docs.tendermint.com/v0.34/introduction/install.html) `==0.34.19`
- [IPFS node](https://docs.ipfs.io/install/command-line/#official-distributions) `==0.6.0`
- [Pip](https://pip.pypa.io/en/stable/installation/)
- [Poetry](https://python-poetry.org/)
- [Docker Engine](https://docs.docker.com/engine/install/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Set Docker permissions so you can run containers as non-root user](https://docs.docker.com/engine/install/linux-postinstall/)


## Run you own agent

### Get the code

1. Clone this repo:

    ```
    git clone git@github.com:kuresh-isotrp/academy-learning-service-template.git
    ```

2. Create the virtual environment:

    ```
    cd academy-learning-service
    poetry shell
    poetry install
    ```

3. Sync packages:

    ```
    autonomy packages sync --update-packages
    ```

### Prepare the data

1. Prepare a `keys.json` file containing wallet address and the private key for each of the four agents.

    ```
    autonomy generate-key ethereum -n 4
    ```

2. Prepare a `ethereum_private_key.txt` file containing one of the private keys from `keys.json`. Ensure that there is no newline at the end.

3. Deploy a [Safe on Gnosis](https://app.safe.global/welcome) (it's free) and set your agent addresses as signers. Set the signature threshold to 3 out of 4.

4. Create a [Tenderly](https://tenderly.co/) account and from your dashboard create a fork of Gnosis chain (virtual testnet).

5. From Tenderly, fund your agents and Safe with a small amount of xDAI, i.e. $0.02 each.

6. Make a copy of the env file:

    ```
    cp sample.env .env
    ```

7. Fill in the required environment variables in .env. These variables are: `ALL_PARTICIPANTS`, `GNOSIS_LEDGER_RPC`, `COINGECKO_API_KEY` , `SAFE_CONTRACT_ADDRESS`. You will need to get a [Coingecko](https://www.coingecko.com/). Set `GNOSIS_LEDGER_RPC` to your Tenderly fork Admin RPC.
     set TRANSFER_TARGET_ADDRESS as the target address where you want to do the transfer
     set SUBGRAPH_URL to read the data and pused to IPFS.In this service we have used Connext Gnosis (https://thegraph.com/explorer/subgraphs/6oJrPk9YJEU9rWU4DAizjZdALSccxe5ZahBsTtFaGksU?                view=Query&chain=arbitrum-one).IN this create subgraph api key to access the subgraph data.
    set MULTI_SEND_CONTRACT_TOKEN_ADDRESS as the token for multisend on gnosis chain
    set TRANSFER_CONTRACT_TOKEN_ADDRESS as the token for ERC-20 on gnosis chain

### Run a single agent

1. Verify that `ALL_PARTICIPANTS` in `.env` contains only 1 address.

2. Run the agent:

    ```
    bash run_agent.sh
    ```

### Run the service (4 agents)

1. Check that Docker is running:

    ```
    docker
    ```

2. Verify that `ALL_PARTICIPANTS` in `.env` contains 4 addresses.

3. Run the service:

    ```
    bash run_service.sh
    ```

4. Look at the service logs for one of the agents (on another terminal):

    ```
    docker logs -f learningservice_abci_0
    ```


