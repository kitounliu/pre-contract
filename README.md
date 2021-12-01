# pre-contract


### Running demo with local Wasmd node
Install wasmd
```
git clone https://github.com/CosmWasm/wasmd.git
cd wasmd
git checkout v0.16.0

make install

# Check if wasmd is properly installed
wasmd version
# Version should be 0.16.0

```



Setup WasmD node
```s
# Initialise test chain

# Clean state 
rm -rf ~/.wasm*

# default home is ~/.wasmd
# initialize wasmd configuration files
wasmd init localnet --chain-id localnet



# create validator address
wasmd keys add validator 

wasmd add-genesis-account $(wasmd keys show validator -a) 100000000000000000000000stake

wasmd gentx validator 10000000000000000000000stake --chain-id localnet

# collect gentxs to genesis
wasmd collect-gentxs 

# validate the genesis file
wasmd validate-genesis 

# Enable rest-api
sed -i '/^\[api\]$/,/^\[/ s/^enable = false/enable = true/' ~/.wasmd/config/app.toml

# run the node
wasmd start
```


To run demo with local CosmWasm network
```s

# Create users and give them some stake
wasmd keys add alice 
wasmd tx send $(wasmd keys show validator -a ) $(wasmd keys show alice -a ) 10000000stake --chain-id localnet
wasmd keys add bob 
wasmd tx send $(wasmd keys show validator -a ) $(wasmd keys show bob -a) 10000000stake  --chain-id localnet


# Check if funds were transfered from validator to alice
wasmd query bank balances $(wasmd keys show -a alice)
```


Compile contract
```
cd pre-contract
RUSTFLAGS='-C link-arg=-s' cargo wasm
```

Deploy and interact with contract
```s
# store contract
RES=$(wasmd tx wasm store pre_contract.wasm --from alice --gas 9000000 --chain-id localnet -y)
CODE_ID=$(wasmd query wasm list-code --chain-id localnet -o json | jq .code_infos[-1].code_id | sed 's/"//g')


# initate contract
INIT=$(jq -n --arg alice $(wasmd keys show -a alice) '{"count": 17}')
wasmd tx wasm instantiate $CODE_ID "$INIT" --from alice --label "pre" --chain-id localnet -y
CONTRACT=$(wasmd query wasm list-contract-by-code $CODE_ID -o json | jq -r .contracts[0])


# query count
GET_COUNT=$(jq -n '{"get_count":{}}')
wasmd query wasm contract-state smart $CONTRACT "$GET_COUNT"

# verify 
VERIFY_CFRAG='{"verify_cfrag": { "cfrag": "Al1KfK/eAd2l2ycPnCiAK2R36m0paGyyUQ+EAAHkf+rjA4CzBpI4mKjYyaL5Vn8zwj0ReJlhMyzd7dFSnDsPx8oPr9bugmrKV9IJM6z+SCOh8+WpRp/Z+9kg5B1f7+wF2iYCvtuH66YTaBoLXehmtzP4w5ltyoJuQM13zDBgtPG6DnADtcP9DLgiEUYDY4+PcUbDJUPT8e6TsQmGTM/4ydM9wgYDttcRvaKi9UmhGrzxGPwAUGQs1y5yDwF6dnjTRV+I/DsClAOmD42wASd6SzK3VwfNUwncz3P8ZxGJSAEQfreblEwCOPvkKnzSioftUasw5X/5Pdyb9QTnmwWJDXGoZcGkVCjQ8skq0zAvL1EsGNOayDL8CEC8KmIChSihd3CKw10dZVp21cD+RXMOolu/7LvI7QIpEpaE6jq3tfsSdZF7kiECGcI4DIzhEcAaHZSBcCJ7YJwh4PnLTuEyLzNxn/IlXN8=", "capsule": "AxpNiVvDT4hH/j7fcJ4v/TuIsYvB7ZCR4BWhftG13l2GA4xUQwzUPRsrTV25xAuP+6uygHJtq/Ftw5/U91wNIkjMePn7lgWhQ8pUW4bNXfUvD8x4SHBfUF5X2xMV0Qpbopc=", "verifying_pk": "A/aEk32S5fpvgf99IRVnCHvqzcCQfnwEqBPp/ohjNmhd", "delegating_pk": "AjpkhTJPWeGxvzvzINaHuej/ersvBFqe4XgKYasSeY6m", "receiving_pk": "ApNCKSk+c6txL58yfKnuSSX/paOd9pAIZ2u7c1bbExmU"}}'
wasmd tx wasm execute $CONTRACT "$VERIFY_CFRAG" --from alice --chain-id localnet -y
