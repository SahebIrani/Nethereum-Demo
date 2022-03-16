using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Contracts;
using Nethereum.HdWallet;
using Nethereum.Hex.HexTypes;
using Nethereum.KeyStore.Model;
using Nethereum.RPC.Eth.DTOs;
using Nethereum.Signer;
using Nethereum.Util;
using Nethereum.Web3;
using Nethereum.Web3.Accounts;
using Nethereum.Web3.Accounts.Managed;
using System.Numerics;

Console.WriteLine("Hello, World!");

// await GetAccountBalanceAsync();
// await TransferEtherToAnAccountAsync();
// await HDWalletsDemoAsync();
// await ManagedAccountsAsync();
// await DeploymentMessageAsync();
// await AccountObjectsAsync();
// await ManageAccountAsync();
// await ManagedChainIDAsync();
// await KeystoreAsync();
// await SmartContractsDeploymentAsync();

Console.ReadKey();

static async Task GetAccountBalanceAsync()
{
    var web3 = new Web3("https://mainnet.infura.io/v3/3b336abb599245e8ae5e4be1123eb70c");
    var balance = await web3.Eth.GetBalance.SendRequestAsync("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae");
    Console.WriteLine($"Balance in Wei: {balance.Value}");

    var etherAmount = Web3.Convert.FromWei(balance.Value);
    Console.WriteLine($"Balance in Ether: {etherAmount}");

    var balanceInWei = balance.Value;
    var balanceInEther = Web3.Convert.FromWei(balance.Value);
    var BackToWei = Web3.Convert.ToWei(balanceInEther);

    Console.WriteLine($"{balanceInWei} = {balanceInEther} = {BackToWei}");
}

static async Task TransferEtherToAnAccountAsync()
{
    //First let's create an account with our private key for the account address 
    var privateKey = "0x7580e7fb49df1c861f0050fae31c2224c6aba908e116b8da44ee8cd927b990b0";
    var account = new Account(privateKey);
    Console.WriteLine("Our account: " + account.Address);
    //Now let's create an instance of Web3 using our account pointing to our nethereum testchain
    var web3 = new Web3(account, "http://testchain.nethereum.com:8545");

    // Check the balance of the account we are going to send the Ether
    var balance = await web3.Eth.GetBalance.SendRequestAsync("0x13f022d72158410433cbd66f5dd8bf6d2d129924");
    Console.WriteLine("Receiver account balance before sending Ether: " + balance.Value + " Wei");
    Console.WriteLine("Receiver account balance before sending Ether: " + Web3.Convert.FromWei(balance.Value) + " Ether");

    // Lets transfer 1.11 Ether
    var transaction = await web3.Eth.GetEtherTransferService().TransferEtherAndWaitForReceiptAsync("0x13f022d72158410433cbd66f5dd8bf6d2d129924", 1.11m);

    balance = await web3.Eth.GetBalance.SendRequestAsync("0x13f022d72158410433cbd66f5dd8bf6d2d129924");
    Console.WriteLine("Receiver account balance after sending Ether: " + balance.Value);
    Console.WriteLine("Receiver account balance after sending Ether: " + Web3.Convert.FromWei(balance.Value) + " Ether");

    //var privateKey = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
    //var account = new Account(privateKey);
    //var web3 = new Web3(account);
    //var toAddress = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";
    //var transaction = await web3.Eth.GetEtherTransferService().TransferEtherAndWaitForReceiptAsync(toAddress, 1.11m);
    //var transaction = await web3.Eth.GetEtherTransferService().TransferEtherAndWaitForReceiptAsync(toAddress, 1.11m, 2);
    //var transaction = web3.Eth.GetEtherTransferService().TransferEtherAndWaitForReceiptAsync(toAddress, 1.11m, 2, new BigInteger(25000));
}

static async Task HDWalletsDemoAsync()
{
    // This samples shows how to create an HD Wallet using BIP32 standard in Ethereum.
    // For simpler context, this allows you to recover your accounts and private keys created with a seed set of words
    // For example Metamask uses 12 words
    // 
    //Nethereum uses internally NBitcoin to derive the private and public keys, for more information on BIP32 check
    //https://programmingblockchain.gitbook.io/programmingblockchain/key_generation/bip_32

    //Initiating a HD Wallet requires a list of words and an optional password to add further entropy (randomness)

    var words = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";
    //Note: do not confuse the password with your Metamask password, Metamask password is used to secure the storage
    var password = "password";
    var wallet = new Wallet(words, password);

    // An HD Wallet is deterministic, it will derive the same number of addresses 
    // given the same seed (wordlist + optional password).

    // All the created accounts can be loaded in a Web3 instance and used as any other account, 
    // we can for instance check the balance of one of them:

    var account = new Wallet(words, password).GetAccount(0);
    Console.WriteLine("The account address is: " + account.Address);

    var web3 = new Web3(account, "http://testchain.nethereum.com:8545");
    //we connect to the Nethereum testchain which has already the account preconfigured with some Ether balance.
    var balance = await web3.Eth.GetBalance.SendRequestAsync(account.Address);
    Console.WriteLine("The account balance is: " + balance.Value);

    //Or transfer some Ether, as the account already has the private key required to sign the transactions.

    var toAddress = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";
    var transactionReceipt = await web3.Eth.GetEtherTransferService()
        .TransferEtherAndWaitForReceiptAsync(toAddress, 2.11m, 2);
    Console.WriteLine($"Transaction {transactionReceipt.TransactionHash} for amount of 2.11 Ether completed");

    //string Words = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";
    //string Password = "password";
    //var wallet = new Wallet(Words, Password);
    //var account = wallet.GetAccount(0);
    //var toAddress = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";
    //var web3 = new Web3(account);
    //var transaction = await web3.Eth.GetEtherTransferService()
    //                .TransferEtherAndWaitForReceiptAsync(toAddress, 1.11m, 2);

    //--------

    //string Words = "ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal";
    //string Password1 = "password";
    //var wallet1 = new Wallet(Words, Password1);
    //for (int i = 0; i < 10; i++)
    //{
    //    var account = wallet1.GetAccount(i);
    //    Console.WriteLine("Account index : " + i + " - Address : " + account.Address + " - Private key : " + account.PrivateKey);
    //}

    //var account1 = new Wallet(Words, Password1).GetAccount(0);

    //var web3 = new Web3(account1);
    //var balance = await web3.Eth.GetBalance.SendRequestAsync(account1.Address);

    //var toAddress = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";
    //var transaction = await web3.Eth.GetEtherTransferService().TransferEtherAndWaitForReceiptAsync(toAddress, 2.11m, 2);

    //Mnemonic mnemo = new Mnemonic(Wordlist.English, WordCount.Twelve);

    //string Password2 = "password2";
    //var wallet2 = new Wallet(mnemo.ToString(), Password2);
    //var account2 = wallet2.GetAccount(0);

    //var backupSeed = mnemo.ToString();

    //var wallet3 = new Wallet(backupSeed, Password2);
    //var recoveredAccount = wallet3.GetAccount(0);
}

static async Task ManagedAccountsAsync()
{
    var senderAddress = "0x12890d2cce102216644c59daE5baed380d84830c";
    var password = "password";
    var account = new ManagedAccount(senderAddress, password);
    var web3 = new Web3(account, "http://127.0.0.1:8545");

    //using Nethereum.Web3;
    //var web3 = new Web3();
    //var account = await web3.Personal.NewAccount.SendRequestAsync("password");
}

static async Task DeploymentMessageAsync()
{
    var senderAddress = "0x12890d2cce102216644c59daE5baed380d84830c";
    var password = "password";
    var account = new ManagedAccount(senderAddress, password);
    var web3 = new Web3(account, "http://127.0.0.1:8545");

    var deploymentMessage = new StandardTokenDeployment
    {
        TotalSupply = 100000
    };

    var deploymentHandler = web3.Eth.GetContractDeploymentHandler<StandardTokenDeployment>();
    var transactionReceipt1 = await deploymentHandler.SendRequestAndWaitForReceiptAsync(deploymentMessage);
    var contractAddress1 = transactionReceipt1.ContractAddress;

    var balanceOfFunctionMessage = new BalanceOfFunction()
    {
        Owner = account.Address,
    };

    var balanceHandler = web3.Eth.GetContractQueryHandler<BalanceOfFunction>();
    var balance = await balanceHandler.QueryAsync<BigInteger>(contractAddress1, balanceOfFunctionMessage);

    var receiverAddress = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    var transferHandler = web3.Eth.GetContractTransactionHandler<TransferFunction>();
    var transfer = new TransferFunction()
    {
        To = receiverAddress,
        TokenAmount = 100
    };
    var transactionReceipt2 = await transferHandler.SendRequestAndWaitForReceiptAsync(contractAddress1, transfer);
    var transactionHash = transactionReceipt2.TransactionHash;
}

static async Task AccountObjectsAsync()
{
    var privateKey = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";
    var account = new Account(privateKey);

    var web3 = new Web3(account, "http://127.0.0.1:8545");

    var toAddress = "0x12890D2cce102216644c59daE5baed380d84830c";
    var transaction = await web3.TransactionManager.SendTransactionAsync(account.Address, toAddress, new Nethereum.Hex.HexTypes.HexBigInteger(1));

    var senderAddress = "0x12890d2cce102216644c59daE5baed380d84830c";
    var addressTo = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";
    var password = "password";
    var managedAccount = new ManagedAccount(senderAddress, password);
    var web3ManagedAccount = new Web3(managedAccount);

    var transactionManagedAccount = await web3.TransactionManager.SendTransactionAsync(account.Address, addressTo, new HexBigInteger(20));
}

static async Task ManageAccountAsync()
{
    var senderAddress = "0x12890d2cce102216644c59daE5baed380d84830c";
    var password = "password";
    var account = new ManagedAccount(senderAddress, password);
    var web3 = new Web3(account);

    var deploymentMessage = new StandardTokenDeployment
    {
        TotalSupply = 100000
    };
    var deploymentHandler = web3.Eth.GetContractDeploymentHandler<StandardTokenDeployment>();
    var transactionReceipt1 = await deploymentHandler.SendRequestAndWaitForReceiptAsync(deploymentMessage);
    var contractAddress1 = transactionReceipt1.ContractAddress;

    var balanceOfFunctionMessage = new BalanceOfFunction()
    {
        Owner = account.Address,
    };
    var balanceHandler = web3.Eth.GetContractQueryHandler<BalanceOfFunction>();
    var balance = await balanceHandler.QueryAsync<BigInteger>(contractAddress1, balanceOfFunctionMessage);

    var receiverAddress = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    var transferHandler = web3.Eth.GetContractTransactionHandler<TransferFunction>();
    var transfer = new TransferFunction()
    {
        To = receiverAddress,
        TokenAmount = 100
    };
    var transactionReceipt2 = await transferHandler.SendRequestAndWaitForReceiptAsync(contractAddress1, transfer);
    var transactionHash = transactionReceipt2.TransactionHash;
}

static async Task ManagedChainIDAsync()
{
    var privatekey = "0xb5b1870957d373ef0eeffecc6e4812c0fd08f554b37b233526acc331bf1544f7";

    var account = new Account(privatekey, Chain.MainNet);

    account = new Account(privatekey, 444444444500);

    var web3 = new Web3(account);

    var toAddress = "0x13f022d72158410433cbd66f5dd8bf6d2d129924";

    var wei = Web3.Convert.ToWei(1);

    var transactionReceipt = await web3.TransactionManager.TransactionReceiptService.SendRequestAndWaitForReceiptAsync(
              new TransactionInput() { From = account.Address, To = toAddress, Value = new HexBigInteger(wei) }, null);

    var balance = await web3.Eth.GetBalance.SendRequestAsync("0x13f022d72158410433cbd66f5dd8bf6d2d129924");
    var amountInEther = Web3.Convert.FromWei(balance.Value);
}

static async Task KeystoreAsync()
{
    var keyStoreService = new Nethereum.KeyStore.KeyStoreScryptService();
    var scryptParams = new ScryptParams { Dklen = 32, N = 262144, R = 1, P = 8 };
    var ecKey = EthECKey.GenerateKey();
    var password = "testPassword";
    var keyStore = keyStoreService.EncryptAndGenerateKeyStore(password, ecKey.GetPrivateKeyAsBytes(), ecKey.GetPublicAddress(), scryptParams);
    var json = keyStoreService.SerializeKeyStoreToJson(keyStore);
    var key = keyStoreService.DecryptKeyStoreFromJson(password, json);
}

static async Task SmartContractsDeploymentAsync()
{

    // ### Instantiating Web3 and the Account
    // To create an instance of web3 we first provide the url of our testchain and the private key of our account. 
    // Here we are using http://testchain.nethereum.com:8545 which is our simple single node Nethereum testchain.
    // When providing an Account instantiated with a  private key, all our transactions will be signed by Nethereum.

    var url = "http://testchain.nethereum.com:8545";
    var privateKey = "0x7580e7fb49df1c861f0050fae31c2224c6aba908e116b8da44ee8cd927b990b0";
    var account = new Account(privateKey);
    var web3 = new Web3(account, url);

    // **** DEPLOYING THE SMART CONTRACT
    // The next step is to deploy our Standard Token ERC20 smart contract, 
    //in this scenario the total supply (number of tokens) is going to be 100,000.

    // First we create an instance of the StandardTokenDeployment with the TotalSupply amount.

    var deploymentMessage = new StandardTokenDeployment
    {
        TotalSupply = 100000
    };

    // Then we create a deployment handler using our contract deployment definition and simply deploy the contract 
    // using the deployment message. 
    // We are auto estimating the gas, getting the latest gas price and nonce so nothing else is set on the deployment message.
    // Finally, we wait for the deployment transaction to be mined, 
    // and retrieve the contract address of the new contract from the receipt.

    var deploymentHandler = web3.Eth.GetContractDeploymentHandler<StandardTokenDeployment>();
    var transactionReceiptDeployment = await deploymentHandler.SendRequestAndWaitForReceiptAsync(deploymentMessage);
    var contractAddress = transactionReceiptDeployment.ContractAddress;
    Console.WriteLine("Smart contract deployed at address:" + contractAddress);

    // *** INTERACTING WITH THE CONTRACT

    // #### QUERING

    // To retrieve the balance, we will create a QueryHandler and finally using our contract address 
    // and message retrieve the balance amount.

    var balanceOfFunctionMessage = new BalanceOfFunction()
    {
        Owner = account.Address,
    };

    var balanceHandler = web3.Eth.GetContractQueryHandler<BalanceOfFunction>();

    var balance = await balanceHandler.QueryAsync<BigInteger>(contractAddress, balanceOfFunctionMessage);

    Console.WriteLine("Balance of deployment owner address: " + balance);

    // When Quering retrieving multiple results, we can use this method instead

    var balanceOutput =
        await balanceHandler.QueryDeserializingToObjectAsync<GetStartedSmartContracts.BalanceOfOutputDTO>(balanceOfFunctionMessage,
            contractAddress);

    // #### Transfer
    // Making a transfer will change the state of the blockchain, 
    // so in this scenario we will need to create a TransactionHandler using the TransferFunction definition.

    // In the transfer message, we will include the receiver address "To", and the "TokenAmount" to transfer.
    // The final step is to Send the request, wait for the receipt to be “mined” and included in the blockchain.
    // Another option will be to not wait (poll) for the transaction to be mined and just retrieve the transaction hash.

    var receiverAddress = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    var transferHandler = web3.Eth.GetContractTransactionHandler<TransferFunction>();

    var transfer = new TransferFunction()
    {
        To = receiverAddress,
        TokenAmount = 100
    };

    var transactionTransferReceipt =
        await transferHandler.SendRequestAndWaitForReceiptAsync(contractAddress, transfer);
    Console.WriteLine("Transaction hash transfer is: " + transactionTransferReceipt.TransactionHash);

    balance = await balanceHandler.QueryAsync<BigInteger>(contractAddress, balanceOfFunctionMessage);

    Console.WriteLine("Balance of deployment owner address after transfer: " + balance);

    // #### Querying previous state of the smart contract

    // Another great feature of the Ethereum blockchain is the capability to retrieve the state 
    // of a smart contract from a previous block.

    // For example, we could get the balance of the owner at the time of deployment by using the block number 
    // in which the contract was deployed we will get the 10000

    balanceOutput = await balanceHandler.QueryDeserializingToObjectAsync<GetStartedSmartContracts.BalanceOfOutputDTO>(
        balanceOfFunctionMessage, contractAddress, new BlockParameter(transactionReceiptDeployment.BlockNumber));

    Console.WriteLine("Balance of deployment owner address from previous Block Number: " +
transactionReceiptDeployment.BlockNumber + " is: " + balanceOutput.Balance);

    // ##### Transferring Ether to a smart contract

    // A function or deployment transaction can send Ether to the smart contract. The FunctionMessage and DeploymentMessage have the property "AmountToSend".

    // So if the "transfer" function also accepts Ether, we will set it this way.

    transfer.AmountToSend = Web3.Convert.ToWei(1);

    // The GasPrice is set in "Wei" which is the lowest unit in Ethereum, so in the scenario above we have converted 1 Ether to Wei.
    // ### Gas Price

    // Nethereum automatically sets the GasPrice if not provided by using the clients "GasPrice" call, which provides the average gas price from previous blocks.

    // If you want to have more control over the GasPrice these can be set in both FunctionMessages and DeploymentMessages.

    transfer.GasPrice = Web3.Convert.ToWei(25, UnitConversion.EthUnit.Gwei);

    // The GasPrice is set in "Wei" which is the lowest unit in Ethereum, so if we are used to the usual "Gwei" units, this will need to be converted using the Nethereum Convertion utilities.

    // ### Estimating Gas

    // Nethereum does an automatic estimation of the total gas necessary to make the function transaction by calling the "EthEstimateGas" internally with the "CallInput".

    // If needed, this can be done manually, using the TransactionHandler and the "transfer" transaction FunctionMessage.

    var estimate = await transferHandler.EstimateGasAsync(contractAddress, transfer);

    transfer.Gas = estimate.Value;

    // ### Nonces
    // Each account transaction has a Nonce associated with it, this is the order and unique number for that transaction. This allows each transaction to be differentiated from each other, but also ensure transactions are processed in the same order.

    // Nethereum calculates the Nonce automatically for all Transactions by retrieving the latest count of the transactions from the chain. Also internally manages at Account level an in memory counter on the nonces, to allow for situations in which we want to send multiple transactions before giving time to the Ethereum client to update its internal counter.
    // Nevertheless there might be scenarios where we want to supply our Nonce, for example if we want to sign the transaction completely offline.

    transfer.Nonce = 2;

    // ### Signing a Function / Deployment message online / offline

    // The TransactionHandler also provides a mechanism to sign the Function and Deployments messages, provided we use an Account and/or an ExternalAccount

    var signedTransaction1 = await transferHandler.SignTransactionAsync(contractAddress, transfer);

    Console.WriteLine("SignedTransaction is: " + signedTransaction1);

    // Nethereum internally calls the Ethereum client to set the GasPrice, Nonce and estimate the Gas, 
    // so if we want to sign the transaction for the contract completely offline we will need to set those values before hand.

    transfer.Nonce = 2;

    transfer.Gas = 21000;

    transfer.GasPrice = Web3.Convert.ToWei(25, UnitConversion.EthUnit.Gwei);

    var signedTransaction2 = await transferHandler.SignTransactionAsync(contractAddress, transfer);

    Console.WriteLine(
        " Full offline (no need for node) Signed Transaction (providing manually the nonce, gas and gas price) is: " +
        signedTransaction2);
}

public class StandardTokenDeployment : ContractDeploymentMessage
{
    public static string BYTECODE = "0x60606040526040516020806106f5833981016040528080519060200190919050505b80600160005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005081905550806000600050819055505b506106868061006f6000396000f360606040523615610074576000357c010000000000000000000000000000000000000000000000000000000090048063095ea7b31461008157806318160ddd146100b657806323b872dd146100d957806370a0823114610117578063a9059cbb14610143578063dd62ed3e1461017857610074565b61007f5b610002565b565b005b6100a060048080359060200190919080359060200190919050506101ad565b6040518082815260200191505060405180910390f35b6100c36004805050610674565b6040518082815260200191505060405180910390f35b6101016004808035906020019091908035906020019091908035906020019091905050610281565b6040518082815260200191505060405180910390f35b61012d600480803590602001909190505061048d565b6040518082815260200191505060405180910390f35b61016260048080359060200190919080359060200190919050506104cb565b6040518082815260200191505060405180910390f35b610197600480803590602001909190803590602001909190505061060b565b6040518082815260200191505060405180910390f35b600081600260005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060008573ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905061027b565b92915050565b600081600160005060008673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050541015801561031b575081600260005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060003373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000505410155b80156103275750600082115b1561047c5781600160005060008573ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a381600160005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282825054039250508190555081600260005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060003373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505403925050819055506001905061048656610485565b60009050610486565b5b9392505050565b6000600160005060008373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000505490506104c6565b919050565b600081600160005060003373ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050541015801561050c5750600082115b156105fb5781600160005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282825054039250508190555081600160005060008573ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505401925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905061060556610604565b60009050610605565b5b92915050565b6000600260005060008473ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060008373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005054905061066e565b92915050565b60006000600050549050610683565b9056";

    public StandardTokenDeployment() : base(BYTECODE) { }

    [Parameter("uint256", "totalSupply")]
    public BigInteger TotalSupply { get; set; }
}

[Function("balanceOf", "uint256")]
public class BalanceOfFunction : FunctionMessage
{
    [Parameter("address", "_owner", 1)]
    public string Owner { get; set; }
}

[Function("transfer", "bool")]
public class TransferFunction : FunctionMessage
{
    [Parameter("address", "_to", 1)]
    public string To { get; set; }

    [Parameter("uint256", "_value", 2)]
    public BigInteger TokenAmount { get; set; }
}

public class GetStartedSmartContracts
{
    /* Quick introduction to smart contracts integration with Nethereum

        Topics covered:

         * Understanding how to create contract deployment, function and event definitions to interact with a smart contracts
         * Creating an account object using a private key, this will allow to sign transactions "offline".
         * Deploying a smart contract (the sample provided is the standard ERC20 token contract)
         * Making a call to a smart contract (in this scenario get the balance of an account)
         * Sending a transaction to the smart contract (in this scenario transferring balance)
         * Estimating the gas cost of a contract transaction
         * Gas Price, Nonces and Sending Ether to smart contracts
            * Retrieving the state of a smart contract from a previous block
    */

    //********* CONTRACT DEFINITION  *******

    //*** Deployment message**** //
    // To deploy a contract we will create a class inheriting from the ContractDeploymentMessage, 
    // here we can include our compiled byte code and other constructor parameters.
    // As we can see below the StandardToken deployment message includes the compiled bytecode 
    // of the ERC20 smart contract and the constructor parameter with the “totalSupply” of tokens.
    // Each parameter is described with an attribute Parameter, including its name "totalSupply", type "uint256" and order.

    public class StandardTokenDeployment : ContractDeploymentMessage
    {
        public static string BYTECODE =
            "0x60606040526040516020806106f5833981016040528080519060200190919050505b80600160005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005081905550806000600050819055505b506106868061006f6000396000f360606040523615610074576000357c010000000000000000000000000000000000000000000000000000000090048063095ea7b31461008157806318160ddd146100b657806323b872dd146100d957806370a0823114610117578063a9059cbb14610143578063dd62ed3e1461017857610074565b61007f5b610002565b565b005b6100a060048080359060200190919080359060200190919050506101ad565b6040518082815260200191505060405180910390f35b6100c36004805050610674565b6040518082815260200191505060405180910390f35b6101016004808035906020019091908035906020019091908035906020019091905050610281565b6040518082815260200191505060405180910390f35b61012d600480803590602001909190505061048d565b6040518082815260200191505060405180910390f35b61016260048080359060200190919080359060200190919050506104cb565b6040518082815260200191505060405180910390f35b610197600480803590602001909190803590602001909190505061060b565b6040518082815260200191505060405180910390f35b600081600260005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060008573ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905061027b565b92915050565b600081600160005060008673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050541015801561031b575081600260005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060003373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000505410155b80156103275750600082115b1561047c5781600160005060008573ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a381600160005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282825054039250508190555081600260005060008673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060003373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505403925050819055506001905061048656610485565b60009050610486565b5b9392505050565b6000600160005060008373ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000505490506104c6565b919050565b600081600160005060003373ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600050541015801561050c5750600082115b156105fb5781600160005060003373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282825054039250508190555081600160005060008573ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828282505401925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a36001905061060556610604565b60009050610605565b5b92915050565b6000600260005060008473ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005060008373ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060005054905061066e565b92915050565b60006000600050549050610683565b9056";

        public StandardTokenDeployment() : base(BYTECODE)
        {
        }

        [Parameter("uint256", "totalSupply")]
        public BigInteger TotalSupply { get; set; }
    }

    //*** FUNCTION MESSAGES **** ///

    // We can call the functions of smart contract to query the state of a smart contract or do any computation, 
    // which will not affect the state of the blockchain.

    // To do so,  we will need to create a class which inherits from "FunctionMessage". 
    // First we will decorate the class with a "Function" attribute, including the name and return type.
    // Each parameter of the function will be a property of the class, each of them decorated with the "Parameter" attribute, 
    // including the smart contract’s parameter name, type and parameter order.
    // For the ERC20 smart contract, the "balanceOf" function definition, 
    // provides the query interface to get the token balance of a given address. 
    // As we can see this function includes only one parameter "\_owner", of the type "address".

    [Function("balanceOf", "uint256")]
    public class BalanceOfFunction : FunctionMessage
    {
        [Parameter("address", "_owner", 1)]
        public string Owner { get; set; }
    }

    // Another type of smart contract function will be a transaction 
    // that will change the state of the smart contract (or smart contracts).
    // For example The "transfer" function definition for the ERC20 smart contract, 
    // includes the parameters “\_to”, which is an address parameter as a string, and the “\_value” 
    // or TokenAmount we want to transfer.

    // In a similar way to the "balanceOf" function, all the parameters include the solidity type, 
    // the contract’s parameter name and parameter order.

    // Note: When working with functions, it is very important to have the parameters types and function name correct 
    //as all of these make the signature of the function.

    [Function("transfer", "bool")]
    public class TransferFunction : FunctionMessage
    {
        [Parameter("address", "_to", 1)]
        public string To { get; set; }

        [Parameter("uint256", "_value", 2)]
        public BigInteger TokenAmount { get; set; }
    }

    // Finally, smart contracts also have events. Events defined in smart contracts write in the blockchain log, 
    // providing a way to retrieve further information when a smart contract interaction occurs.
    // To create an Event definition, we need to create a class that inherits from IEventDTO, decorated with the Event attribute.
    // The Transfer Event is similar to a Function: it  also includes parameters with name, order and type. 
    // But also a boolean value indicating if the parameter is indexed or not.
    // Indexed parameters will allow us later on to query the blockchain for those values.

    [Event("Transfer")]
    public class TransferEventDTO : IEventDTO
    {
        [Parameter("address", "_from", 1, true)]
        public string From { get; set; }

        [Parameter("address", "_to", 2, true)]
        public string To { get; set; }

        [Parameter("uint256", "_value", 3, false)]
        public BigInteger Value { get; set; }
    }

    // ### Multiple return types or complex objects
    // Functions of smart contracts can return one or multiple values in a single call. To decode the returned values, we use a FunctionOutputDTO.
    // Function outputs are classes which are decorated with a FunctionOutput attribute and implement the interface IFunctionOutputDTO.
    // An example of this is the following implementation that can be used to return the single value of the Balance on the ERC20 smart contract.

    [FunctionOutput]
    public class BalanceOfOutputDTO : IFunctionOutputDTO
    {
        [Parameter("uint256", "balance", 1)]
        public BigInteger Balance { get; set; }
    }

    // If we were going to return multiple values we could have something like:

    [FunctionOutput]
    public class BalanceOfOutputMultipleDTO : IFunctionOutputDTO
    {
        [Parameter("uint256", "balance1", 1)]
        public BigInteger Balance1 { get; set; }

        [Parameter("uint256", "balance2", 2)]
        public BigInteger Balance2 { get; set; }

        [Parameter("uint256", "balance3", 3)]
        public BigInteger Balance3 { get; set; }
    }

    //**** END CONTRACT DEFINITIONS ***** ///
}