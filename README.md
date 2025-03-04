# Smart Contract & Blockchain Encoding Cheatsheet 🔍

## Basic Encodings

### Base58
- **Karakteristik:** Alphanumeric tanpa 0, O, I, l, +, /
- **Use Cases:** Bitcoin addresses, IPFS hashes
- **Example:** `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2`
- **Vulnerability Points:** Decoder overflow, improper padding handling

### Base58Check
- **Karakteristik:** Base58 + checksum
- **Use Cases:** Bitcoin addresses dengan error detection
- **Example:** `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`
- **Vulnerability Points:** Checksum bypass, version byte manipulation

### Base64
- **Karakteristik:** A-Z, a-z, 0-9, +, /
- **Use Cases:** Data encoding di smart contracts
- **Example:** `TWFuIGlzIGRpc3Rpbmd1aXNoZWQ=`
- **Vulnerability Points:** Padding oracle, buffer overflow

### Base32
- **Karakteristik:** A-Z, 2-7
- **Use Cases:** IPFS CIDv1
- **Example:** `JBSWY3DPEHPK3PXP`
- **Vulnerability Points:** Case sensitivity issues

## Blockchain Specific

### Keccak256
- **Karakteristik:** 256-bit hash
- **Use Cases:** Ethereum transaction hashing
- **Example:** `0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
- **Vulnerability Points:** Collision attacks, length extension

### RLP (Recursive Length Prefix)
- **Karakteristik:** Ethereum data serialization
- **Use Cases:** Transaction encoding
- **Example:** `0xf86d8202b28477359400825208944592d8f8d7b001e72cb26a73e4fa1806a51ac79d880de0b6b3a7640000802ca05924bde7ef10aa88db9c66dd4f5fb16b46dff2319b9968be983118b57bb50562a001b24b31010004f13d9a26b320845257a6cfc2bf819a3d55e3fc86263c5f0772`
- **Vulnerability Points:** Integer overflow, nested depth attacks

### ABI Encoding
- **Karakteristik:** Function signatures & parameter encoding
- **Use Cases:** Smart contract interaction
- **Example:** `0xa9059cbb000000000000000000000000...`
- **Vulnerability Points:** Padding attacks, type confusion

## Advanced Encodings

### Hex Encoding
- **Karakteristik:** 0-9, a-f
- **Use Cases:** Raw transaction data
- **Example:** `0x123f4522...`
- **Vulnerability Points:** Length validation, odd-length handling

### Bech32
- **Karakteristik:** Base32 + error correction
- **Use Cases:** Native SegWit addresses
- **Example:** `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`
- **Vulnerability Points:** Checksum manipulation

### Base16
- **Karakteristik:** Hexadecimal
- **Use Cases:** Raw data representation
- **Example:** `A1B2C3D4`
- **Vulnerability Points:** Case sensitivity

## Smart Contract Specific

### Solidity Tight Packing
- **Karakteristik:** No padding between values
- **Use Cases:** keccak256(abi.encodePacked())
- **Example:** `bytes.concat(bytes1(0x42), bytes1(0x43))`
- **Vulnerability Points:** Hash collision due to different arrangements

### Storage Layout Encoding
- **Karakteristik:** 32-byte slot based
- **Use Cases:** Contract storage
- **Example:** `mapping(address => uint256)`
- **Vulnerability Points:** Slot collision, packing vulnerabilities

### Event Topics Encoding
- **Karakteristik:** Indexed parameters
- **Use Cases:** Event logs
- **Example:** `event Transfer(address indexed from, address indexed to, uint256 value)`
- **Vulnerability Points:** Topic manipulation

## Attack & Defense Patterns 🗡️🛡️

### Base58 & Base58Check
**Attack Vectors:**
```solidity
// 1. Decoder Overflow
function maliciousInput() public {
    // Input dengan panjang yang extreme
    string memory evil = "1" + new string(1000000); 
    decode58(evil); // Trigger overflow
}

// 2. Checksum Manipulation
function bypassCheck() public {
    // Manipulasi version byte
    bytes memory addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    addr[0] = 0x00; // Ubah version byte
}
```

**Defense:**
```solidity
// 1. Length Validation
function safeBase58Decode(string memory input) public {
    require(bytes(input).length <= MAX_LENGTH, "Input too long");
    // proceed with decoding
}

// 2. Strict Checksum
function validateAddress(bytes memory addr) public {
    require(validateChecksum(addr), "Invalid checksum");
    require(validateVersion(addr[0]), "Invalid version");
}
```

### ABI Encoding
**Attack Vectors:**
```solidity
// 1. Parameter Confusion
function attackABI() public {
    // Encode dengan tipe yang salah
    bytes memory data = abi.encode(uint256(100)); // Harusnya address
    target.call(data);
}

// 2. Padding Attack
function paddingAttack() public {
    bytes memory evil = new bytes(32);
    evil[31] = 0xff;
    // Trigger overflow dengan padding
}
```

**Defense:**
```solidity
// 1. Strict Type Checking
function safeCall(address target, bytes memory data) public {
    require(data.length >= 4, "Invalid ABI");
    bytes4 selector = bytes4(data[:4]);
    require(validSelector(selector), "Invalid selector");
}

// 2. Safe Decoding
function safeDecode(bytes memory data) public {
    try abi.decode(data, (address, uint256)) returns (address a, uint256 b) {
        // Valid decode
    } catch {
        revert("Invalid encoding");
    }
}
```

### Keccak256
**Attack Vectors:**
```solidity
// 1. Length Extension
function lengthAttack() public {
    bytes memory msg1 = "message";
    bytes memory msg2 = abi.encodePacked(msg1, padding);
    // Hash collision possible
}

// 2. Preimage Attack
function preimageAttack() public {
    bytes32 target = 0x123...;
    // Brute force untuk find collision
}
```

**Defense:**
```solidity
// 1. Domain Separation
function safeHash(string memory input) public {
    return keccak256(abi.encodePacked("DOMAIN:", input));
}

// 2. Multiple Hash Rounds
function strongHash(bytes memory data) public {
    bytes32 h1 = keccak256(data);
    bytes32 h2 = keccak256(abi.encodePacked(h1, data));
    return h2;
}
```

### RLP Encoding
**Attack Vectors:**
```solidity
// 1. Nested Depth Attack
function depthAttack() public {
    // Create deeply nested array
    bytes[] memory nested = createDeepNesting(1000);
    bytes memory rlp = RLPEncode(nested);
}

// 2. Integer Overflow
function overflowAttack() public {
    uint256 evil = type(uint256).max;
    bytes memory rlp = RLPEncode(evil);
}
```

**Defense:**
```solidity
// 1. Depth Limit
function safeRLPDecode(bytes memory rlp) public {
    uint256 depth = 0;
    require(checkDepth(rlp, depth), "Nesting too deep");
}

// 2. Size Validation
function validateRLP(bytes memory rlp) public {
    require(rlp.length <= MAX_RLP_LENGTH, "RLP too long");
    require(validateRLPStructure(rlp), "Invalid structure");
}
```

### Storage Layout
**Attack Vectors:**
```solidity
// 1. Slot Collision
contract VulnerableContract {
    mapping(address => uint256) balances;
    mapping(address => uint256) rewards;
    // Slot collision possible
}

// 2. Packing Exploit
contract BadPacking {
    uint128 a;
    uint128 b;
    // Can be packed dangerously
}
```

**Defense:**
```solidity
// 1. Slot Separation
contract SafeContract {
    bytes32 constant BALANCES_SLOT = keccak256("balances");
    bytes32 constant REWARDS_SLOT = keccak256("rewards");
    
    function getBalanceSlot(address user) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, BALANCES_SLOT));
    }
}

// 2. Safe Packing
contract GoodPacking {
    struct SafeData {
        uint128 a;
        uint128 b;
    }
    mapping(address => SafeData) userData;
}
```

## Security Best Practices 🔒

### Input Validation
```solidity
modifier validateInput(bytes memory data) {
    require(data.length > 0, "Empty input");
    require(data.length <= MAX_INPUT, "Input too long");
    require(validateFormat(data), "Invalid format");
    _;
}
```

### Error Handling
```solidity
function safeOperation() public returns (bool) {
    try this.riskyOperation() returns (bool success) {
        return success;
    } catch (bytes memory reason) {
        emit OperationFailed(reason);
        return false;
    }
}
```

### Access Control
```solidity
modifier onlyAuthorized(bytes memory signature) {
    bytes32 hash = keccak256(abi.encodePacked(msg.sender, block.timestamp));
    address signer = recoverSigner(hash, signature);
    require(isAuthorized(signer), "Unauthorized");
    _;
}
```

### Monitoring & Logging
```solidity
event EncodingOperation(
    address indexed user,
    bytes32 indexed dataHash,
    uint256 timestamp
);

function logOperation(bytes memory data) internal {
    emit EncodingOperation(
        msg.sender,
        keccak256(data),
        block.timestamp
    );
}
```

## Security Tips ��

### Common Vulnerabilities
1. Decoder Implementation Bugs
2. Integer Overflow/Underflow
3. Buffer Overflow
4. Type Confusion
5. Padding Oracle
6. Length Extension Attacks

### Best Practices
1. Always validate decoded output
2. Use standard libraries
3. Check for malformed input
4. Implement proper error handling
5. Use constant-time comparison
6. Regular security audits

### Audit Checklist
- [ ] Check encoding/decoding implementations
- [ ] Verify padding handling
- [ ] Test edge cases
- [ ] Review error handling
- [ ] Check for memory safety
- [ ] Validate input boundaries

## Tools for Testing 🛠️

### Popular Tools
1. web3.js
2. ethers.js
3. Truffle
4. Hardhat
5. Foundry
6. Mythril
7. Slither

### Testing Methods
1. Fuzzing
2. Static Analysis
3. Dynamic Analysis
4. Symbolic Execution
5. Manual Review 

## Local Testing & Exploit Simulation 🎯

### Setup Local Environment
```bash
# 1. Setup Hardhat Local Node
npm install --save-dev hardhat
npx hardhat node  # Run local node

# 2. Setup Foundry
forge init
anvil  # Run local node

# 3. Setup Ganache (Alternative)
npm install -g ganache
ganache-cli --fork https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY  # Fork mainnet
```

### Fork Mainnet untuk Testing
```solidity
// Script buat fork mainnet di Hardhat
require("@nomiclabs/hardhat-waffle");

module.exports = {
  networks: {
    hardhat: {
      forking: {
        url: "https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY",
        blockNumber: 15000000 // Specific block for consistent testing
      }
    }
  }
};
```

### Quick Exploit Template
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "./Interface.sol";

contract ExploitTest is Test {
    IERC20 token;
    address victim;
    address attacker;
    
    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", 15000000);
        
        token = IERC20(address(0x...));
        victim = address(0x...);
        attacker = address(0x1337);
        
        // Fund attacker
        vm.deal(attacker, 100 ether);
        // Impersonate account if needed
        vm.prank(victim);
    }
    
    function testExploit() public {
        // Setup initial state
        vm.startPrank(attacker);
        
        // 1. Setup flash loan if needed
        // 2. Execute attack steps
        // 3. Verify exploit success
        
        vm.stopPrank();
        
        // Assert our success conditions
        assertGt(token.balanceOf(attacker), 0);
    }
}
```

### Simulation Tools & Techniques

#### 1. Tenderly Simulation
```javascript
// Script buat simulate transaction
const simulation = await tenderly.simulate({
    network_id: '1',
    from: attacker,
    to: victim,
    input: encodedCalldata,
    gas: 8000000,
    gas_price: '0',
    value: '1000000000000000000' // 1 ETH
});
```

#### 2. Foundry Invariant Testing
```solidity
function invariant_totalSupply() public {
    // This should always be true
    assertEq(token.totalSupply(), INITIAL_SUPPLY);
}

function invariant_balanceSum() public {
    uint256 total;
    for(uint i = 0; i < actors.length; i++) {
        total += token.balanceOf(actors[i]);
    }
    assertEq(total, token.totalSupply());
}
```

#### 3. Echidna Property Testing
```solidity
contract TokenTest {
    Token token;
    address victim;
    
    constructor() public {
        token = new Token();
        victim = address(0x1);
    }
    
    function echidna_balance_under_threshold() public view returns (bool) {
        return token.balanceOf(victim) <= THRESHOLD;
    }
}
```

### Quick Debug Tools

#### 1. Hardhat Console
```solidity
import "hardhat/console.sol";

contract Exploit {
    function attack() public {
        console.log("Attacker balance:", token.balanceOf(msg.sender));
        console.log("Block number:", block.number);
    }
}
```

#### 2. Foundry Traces
```bash
forge test -vvv  # Detailed traces
forge test --debug "testExploit"  # Interactive debugger
```

#### 3. Memory Dumps
```solidity
function dumpState() internal {
    bytes32 slot = keccak256(abi.encodePacked(key));
    bytes32 value = vm.load(address(target), slot);
    console.logBytes32(value);
}
```

### Time-saving Tips 💡

1. **Quick Contract Creation:**
```solidity
// Deploy dengan minimal proxy
function cloneContract(address implementation) internal returns (address) {
    bytes20 targetBytes = bytes20(implementation);
    address clone = address(uint160(uint256(keccak256(abi.encodePacked(
        hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
        targetBytes,
        hex"5af43d82803e903d91602b57fd5bf3"
    )))));
    return clone;
}
```

2. **Flash Setup:**
```solidity
// Quick flash loan setup
interface IFlashloan {
    function flashLoan(
        address receiver,
        address token,
        uint256 amount,
        bytes calldata params
    ) external;
}

// Dalam test:
function setUp() public {
    flashlender = IFlashloan(FLASHLOAN_ADDRESS);
    vm.deal(address(this), 1 ether); // Gas
}
```

3. **State Manipulation:**
```solidity
// Manipulate contract state langsung
function changeState() internal {
    vm.store(
        address(target),
        bytes32(uint256(1)), // slot
        bytes32(uint256(1337)) // new value
    );
}
```

4. **Quick Assert Template:**
```solidity
modifier assertInvariant() {
    _;
    // Quick check semua invariant
    assertGt(attacker.balance, initialBalance);
    assertEq(victim.balance, 0);
    assertTrue(success);
}
``` 

testnet 

# 1. Setup Multi-testnet Environment
npm install -g @truffle/hdwallet-provider

# Quick script buat deploy ke berbagai testnet
networks: {
    sepolia: {
        url: "https://sepolia.infura.io/v3/YOUR_KEY",
        accounts: [PRIVATE_KEY]
    },
    goerli: {
        url: "https://goerli.infura.io/v3/YOUR_KEY",
        accounts: [PRIVATE_KEY]
    },
    mumbai: {
        url: "https://polygon-mumbai.infura.io/v3/YOUR_KEY",
        accounts: [PRIVATE_KEY]
    }
}


template POC :
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TestnetPOC {
    // Addresses di testnet
    address constant VICTIM = 0x...;
    address constant FLASHLOAN = 0x...;
    
    constructor() {
        // Setup initial state
    }
    
    function proveVulnerability() external {
        // 1. Setup preconditions
        require(IERC20(token).balanceOf(address(this)) == 0, "Start with 0");
        
        // 2. Execute exploit
        // ... exploit code ...
        
        // 3. Prove success
        require(IERC20(token).balanceOf(address(this)) > 0, "Exploit success");
        
        // 4. Log everything
        emit ExploitSuccess(
            block.number,
            block.timestamp,
            msg.sender,
            IERC20(token).balanceOf(address(this))
        );
    }
}

Auto Documentation Generator:
event ExploitStep(
    uint256 indexed step,
    string description,
    bytes data
);

function documentStep(uint256 step, string memory desc, bytes memory data) internal {
    emit ExploitStep(step, desc, data);
    
    // Juga log ke console buat debugging
    console.log("Step %s: %s", step, desc);
    console.logBytes(data);
}

Quick Testnet Tools:
// Script buat auto-verify contract
async function verifyContract() {
    await hre.run("verify:verify", {
        address: deployedAddress,
        constructorArguments: [],
    });
}

// Auto faucet requester
async function getFaucetTokens() {
    const faucets = {
        'sepolia': 'https://faucet.sepolia.dev',
        'mumbai': 'https://faucet.polygon.technology'
    };
    // Auto request tokens
}

Pro tips buat handle klien:
Dokumentasi yang Rapi

## Proof of Concept
- Network: Sepolia
- Block: 12345678
- Transaction: 0x...
- Contract: 0x...

## Steps to Reproduce:
1. Deploy POC contract
2. Call proveVulnerability()
3. Check emitted events

Video Recording:
# Record terminal
asciinema rec exploit-demo.cast

# Convert ke gif
agg exploit-demo.cast exploit-demo.gif

Automated Testing:
// Script buat auto test di multiple testnet
async function testAllNetworks() {
    const networks = ['sepolia', 'goerli', 'mumbai'];
    for (let net of networks) {
        console.log(`Testing on ${net}...`);
        await deployAndTest(net);
    }
}
