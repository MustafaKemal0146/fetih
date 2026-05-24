# 0xSimsar — Blockchain Transaction Analysis Walkthrough

**Challenge**: Find a hidden operation codename in BNB Chain transactions.

## Given
- Wallet address: `0xDB53Ed864Eac0d9A401FbAf869F70F60E23FFbb9`
- Network: BNB Chain (BSC)
- Codename leaked in a public transaction record's input data
- Sender alias: "DeLiSimSar" (data broker)

## Approach

### 1. Check Transaction Count (RPC)
```bash
curl -s -X POST "https://bsc-dataseed.binance.org/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getTransactionCount",\
       "params":["0xDB53Ed864Eac0d9A401FbAf869F70F60E23FFbb9","latest"],"id":1}'
```
Response `0x3` = 3 transactions (nonces 0, 1, 2).

### 2. Explorer Access Issues
BSCScan uses aggressive Cloudflare bot detection — browser_navigate is blocked. Alternative explorers:
- `explorer.bnbchain.org` — shows Assets tab but 0 transactions (old BNB Beacon Chain, deprecated)
- `debank.com` — blocks automation
- `oklink.com` — requires API key

### 3. RPC Transaction Search
Without transaction hashes, you need to scan blocks. `eth_getBlockByNumber` with a specific block number:
```bash
curl -s -X POST "https://bsc-dataseed.binance.org/" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber",\
       "params":["latest",true],"id":1}'
```
This returns all transactions in the latest block. Scan `from`/`to` fields for the target address.

For HISTORICAL transactions (old nonces), you need the block number. Without an explorer index:
- Estimate block by creation date
- Search in batches of 1000 blocks
- Use binary search to narrow down

### 4. Input Data Decoding
Transaction `input` field contains hex data. Strip `0x` prefix and decode:
```python
bytes.fromhex(tx['input'][2:]).decode('utf-8', errors='replace')
```

### 5. When Blocked By All Explorers
- Search engines (Google, Bing) may have cached explorer pages
- Twitter/GitHub may have shared transaction links
- Try different RPC URLs: `bsc-dataseed1.binance.org`, `bsc-dataseed2.binance.org`
