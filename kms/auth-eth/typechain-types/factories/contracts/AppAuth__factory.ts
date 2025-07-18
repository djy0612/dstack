/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import {
  Contract,
  ContractFactory,
  ContractTransactionResponse,
  Interface,
} from "ethers";
import type { Signer, ContractDeployTransaction, ContractRunner } from "ethers";
import type { NonPayableOverrides } from "../../common";
import type { AppAuth, AppAuthInterface } from "../../contracts/AppAuth";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "target",
        type: "address",
      },
    ],
    name: "AddressEmptyCode",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "implementation",
        type: "address",
      },
    ],
    name: "ERC1967InvalidImplementation",
    type: "error",
  },
  {
    inputs: [],
    name: "ERC1967NonPayable",
    type: "error",
  },
  {
    inputs: [],
    name: "FailedCall",
    type: "error",
  },
  {
    inputs: [],
    name: "InvalidInitialization",
    type: "error",
  },
  {
    inputs: [],
    name: "NotInitializing",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "OwnableInvalidOwner",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "OwnableUnauthorizedAccount",
    type: "error",
  },
  {
    inputs: [],
    name: "UUPSUnauthorizedCallContext",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "slot",
        type: "bytes32",
      },
    ],
    name: "UUPSUnsupportedProxiableUUID",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bool",
        name: "allowAny",
        type: "bool",
      },
    ],
    name: "AllowAnyDeviceSet",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "ComposeHashAdded",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "ComposeHashRemoved",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "DeviceAdded",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "DeviceRemoved",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint64",
        name: "version",
        type: "uint64",
      },
    ],
    name: "Initialized",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnershipTransferred",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "implementation",
        type: "address",
      },
    ],
    name: "Upgraded",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [],
    name: "UpgradesDisabled",
    type: "event",
  },
  {
    inputs: [],
    name: "UPGRADE_INTERFACE_VERSION",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "addComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "addDevice",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "allowAnyDevice",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedComposeHashes",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    name: "allowedDeviceIds",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "appId",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "disableUpgrades",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "initialOwner",
        type: "address",
      },
      {
        internalType: "address",
        name: "_appId",
        type: "address",
      },
      {
        internalType: "bool",
        name: "_disableUpgrades",
        type: "bool",
      },
      {
        internalType: "bool",
        name: "_allowAnyDevice",
        type: "bool",
      },
      {
        internalType: "bytes32",
        name: "initialDeviceId",
        type: "bytes32",
      },
      {
        internalType: "bytes32",
        name: "initialComposeHash",
        type: "bytes32",
      },
    ],
    name: "initialize",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "address",
            name: "appId",
            type: "address",
          },
          {
            internalType: "bytes32",
            name: "composeHash",
            type: "bytes32",
          },
          {
            internalType: "address",
            name: "instanceId",
            type: "address",
          },
          {
            internalType: "bytes32",
            name: "deviceId",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "mrAggregated",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "mrSystem",
            type: "bytes32",
          },
          {
            internalType: "bytes32",
            name: "osImageHash",
            type: "bytes32",
          },
          {
            internalType: "string",
            name: "tcbStatus",
            type: "string",
          },
          {
            internalType: "string[]",
            name: "advisoryIds",
            type: "string[]",
          },
        ],
        internalType: "struct IAppAuth.AppBootInfo",
        name: "bootInfo",
        type: "tuple",
      },
    ],
    name: "isAppAllowed",
    outputs: [
      {
        internalType: "bool",
        name: "isAllowed",
        type: "bool",
      },
      {
        internalType: "string",
        name: "reason",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "proxiableUUID",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "composeHash",
        type: "bytes32",
      },
    ],
    name: "removeComposeHash",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "deviceId",
        type: "bytes32",
      },
    ],
    name: "removeDevice",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bool",
        name: "_allowAnyDevice",
        type: "bool",
      },
    ],
    name: "setAllowAnyDevice",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "interfaceId",
        type: "bytes4",
      },
    ],
    name: "supportsInterface",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newImplementation",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "upgradeToAndCall",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60a06040523060805234801561001457600080fd5b5061001d610022565b6100d4565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00805468010000000000000000900460ff16156100725760405163f92ee8a960e01b815260040160405180910390fd5b80546001600160401b03908116146100d15780546001600160401b0319166001600160401b0390811782556040519081527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b50565b6080516112e16100fd60003960008181610b0d01528181610b360152610cd901526112e16000f3fe6080604052600436106101145760003560e01c806367b3f22c116100a0578063ad3cb1cc11610064578063ad3cb1cc1461032d578063bf8b211b1461036b578063dfc772231461039b578063ec669036146103bb578063f2fde38b146103d057600080fd5b806367b3f22c14610263578063715018a6146102835780637c4beeb81461029857806380afdea8146102b85780638da5cb5b146102f057600080fd5b80632f6622e5116100e75780632f6622e5146101be5780633440a16a146101ee57806348d8a36a1461020d5780634f1ef2861461022d57806352d1902d1461024057600080fd5b806301ffc9a7146101195780631d2662001461014e5780631e079198146101705780632a8197281461019e575b600080fd5b34801561012557600080fd5b50610139610134366004610fb1565b6103f0565b60405190151581526020015b60405180910390f35b34801561015a57600080fd5b5061016e610169366004610fdb565b610442565b005b34801561017c57600080fd5b5061019061018b366004610ff4565b61049d565b604051610145929190611080565b3480156101aa57600080fd5b5061016e6101b9366004610fdb565b6105d4565b3480156101ca57600080fd5b506101396101d9366004610fdb565b60016020526000908152604090205460ff1681565b3480156101fa57600080fd5b5060025461013990610100900460ff1681565b34801561021957600080fd5b5061016e6102283660046110cf565b610627565b61016e61023b36600461114b565b6108cc565b34801561024c57600080fd5b506102556108eb565b604051908152602001610145565b34801561026f57600080fd5b5061016e61027e366004610fdb565b610908565b34801561028f57600080fd5b5061016e610958565b3480156102a457600080fd5b5061016e6102b336600461120d565b61096c565b3480156102c457600080fd5b506000546102d8906001600160a01b031681565b6040516001600160a01b039091168152602001610145565b3480156102fc57600080fd5b507f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b03166102d8565b34801561033957600080fd5b5061035e604051806040016040528060058152602001640352e302e360dc1b81525081565b6040516101459190611228565b34801561037757600080fd5b50610139610386366004610fdb565b60036020526000908152604090205460ff1681565b3480156103a757600080fd5b5061016e6103b6366004610fdb565b6109bd565b3480156103c757600080fd5b5061016e610a10565b3480156103dc57600080fd5b5061016e6103eb36600461123b565b610a50565b60006303c0f23360e31b6001600160e01b0319831614806104215750638fd3752760e01b6001600160e01b03198316145b8061043c57506301ffc9a760e01b6001600160e01b03198316145b92915050565b61044a610a8e565b60008181526003602052604090819020805460ff19169055517fe0862975ac517b0478d308012afabc4bc37c23874a18144d7f2dfb852ff95c2c906104929083815260200190565b60405180910390a150565b600080546060906001600160a01b03166104ba602085018561123b565b6001600160a01b0316146104fd5750506040805180820190915260148152732bb937b7339030b8381031b7b73a3937b63632b960611b6020820152600092909150565b60208084013560009081526001909152604090205460ff1661055757505060408051808201909152601881527f436f6d706f73652068617368206e6f7420616c6c6f77656400000000000000006020820152600092909150565b600254610100900460ff161580156105835750606083013560009081526003602052604090205460ff16155b156105bb57505060408051808201909152601281527111195d9a58d9481b9bdd08185b1b1bddd95960721b6020820152600092909150565b5050604080516020810190915260008152600192909150565b6105dc610a8e565b60008181526003602052604090819020805460ff19166001179055517f67fc71ab96fe3fa3c6f78e9a00e635d591b7333ce611c0380bc577aac702243b906104929083815260200190565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a008054600160401b810460ff16159067ffffffffffffffff1660008115801561066d5750825b905060008267ffffffffffffffff16600114801561068a5750303b155b905081158015610698575080155b156106b65760405163f92ee8a960e01b815260040160405180910390fd5b845467ffffffffffffffff1916600117855583156106e057845460ff60401b1916600160401b1785555b6001600160a01b038b166107335760405162461bcd60e51b8152602060048201526015602482015274696e76616c6964206f776e6572206164647265737360581b60448201526064015b60405180910390fd5b6001600160a01b038a1661077a5760405162461bcd60e51b815260206004820152600e60248201526d1a5b9d985b1a5908185c1c08125160921b604482015260640161072a565b600080546001600160a01b0319166001600160a01b038c161790556002805461ffff19168a151561ff001916176101008a151502179055861561080b5760008781526003602052604090819020805460ff19166001179055517f67fc71ab96fe3fa3c6f78e9a00e635d591b7333ce611c0380bc577aac702243b906108029089815260200190565b60405180910390a15b851561086057600086815260016020818152604092839020805460ff191690921790915590518781527ffecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af910160405180910390a15b6108698b610ae9565b610871610afa565b610879610afa565b83156108bf57845460ff60401b19168555604051600181527fc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d29060200160405180910390a15b5050505050505050505050565b6108d4610b02565b6108dd82610ba7565b6108e78282610c0c565b5050565b60006108f5610cce565b5060008051602061128c83398151915290565b610910610a8e565b60008181526001602052604090819020805460ff19169055517f755b79bd4b0eeab344d032284a99003b2ddc018b646752ac72d681593a6e8947906104929083815260200190565b610960610a8e565b61096a6000610d17565b565b610974610a8e565b600280548215156101000261ff00199091161790556040517fbb2cdb6c7b362202d40373f87bc4788301cca658f91711ac1662e1ad2cba4a209061049290831515815260200190565b6109c5610a8e565b600081815260016020818152604092839020805460ff191690921790915590518281527ffecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af9101610492565b610a18610a8e565b6002805460ff191660011790556040517f0e5daa943fcd7e7182d0e893d180695c2ea9f6f1b4a1c5432faf14cf17b774e890600090a1565b610a58610a8e565b6001600160a01b038116610a8257604051631e4fbdf760e01b81526000600482015260240161072a565b610a8b81610d17565b50565b33610ac07f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300546001600160a01b031690565b6001600160a01b03161461096a5760405163118cdaa760e01b815233600482015260240161072a565b610af1610d88565b610a8b81610dd1565b61096a610d88565b306001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161480610b8957507f00000000000000000000000000000000000000000000000000000000000000006001600160a01b0316610b7d60008051602061128c833981519152546001600160a01b031690565b6001600160a01b031614155b1561096a5760405163703e46dd60e11b815260040160405180910390fd5b610baf610a8e565b60025460ff1615610a8b5760405162461bcd60e51b815260206004820152602160248201527f557067726164657320617265207065726d616e656e746c792064697361626c656044820152601960fa1b606482015260840161072a565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa925050508015610c66575060408051601f3d908101601f19168201909252610c6391810190611256565b60015b610c8e57604051634c9c8ce360e01b81526001600160a01b038316600482015260240161072a565b60008051602061128c8339815191528114610cbf57604051632a87526960e21b81526004810182905260240161072a565b610cc98383610dd9565b505050565b306001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461096a5760405163703e46dd60e11b815260040160405180910390fd5b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b7ff0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a0054600160401b900460ff1661096a57604051631afcd79f60e31b815260040160405180910390fd5b610a58610d88565b610de282610e2f565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a2805115610e2757610cc98282610e94565b6108e7610f0a565b806001600160a01b03163b600003610e6557604051634c9c8ce360e01b81526001600160a01b038216600482015260240161072a565b60008051602061128c83398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b031684604051610eb1919061126f565b600060405180830381855af49150503d8060008114610eec576040519150601f19603f3d011682016040523d82523d6000602084013e610ef1565b606091505b5091509150610f01858383610f29565b95945050505050565b341561096a5760405163b398979f60e01b815260040160405180910390fd5b606082610f3e57610f3982610f88565b610f81565b8151158015610f5557506001600160a01b0384163b155b15610f7e57604051639996b31560e01b81526001600160a01b038516600482015260240161072a565b50805b9392505050565b805115610f985780518082602001fd5b60405163d6bda27560e01b815260040160405180910390fd5b600060208284031215610fc357600080fd5b81356001600160e01b031981168114610f8157600080fd5b600060208284031215610fed57600080fd5b5035919050565b60006020828403121561100657600080fd5b813567ffffffffffffffff81111561101d57600080fd5b82016101208185031215610f8157600080fd5b60005b8381101561104b578181015183820152602001611033565b50506000910152565b6000815180845261106c816020860160208601611030565b601f01601f19169290920160200192915050565b821515815260406020820152600061109b6040830184611054565b949350505050565b80356001600160a01b03811681146110ba57600080fd5b919050565b803580151581146110ba57600080fd5b60008060008060008060c087890312156110e857600080fd5b6110f1876110a3565b95506110ff602088016110a3565b945061110d604088016110bf565b935061111b606088016110bf565b92506080870135915060a087013590509295509295509295565b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561115e57600080fd5b611167836110a3565b9150602083013567ffffffffffffffff8082111561118457600080fd5b818501915085601f83011261119857600080fd5b8135818111156111aa576111aa611135565b604051601f8201601f19908116603f011681019083821181831017156111d2576111d2611135565b816040528281528860208487010111156111eb57600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b60006020828403121561121f57600080fd5b610f81826110bf565b602081526000610f816020830184611054565b60006020828403121561124d57600080fd5b610f81826110a3565b60006020828403121561126857600080fd5b5051919050565b60008251611281818460208701611030565b919091019291505056fe360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca26469706673582212209b83d396bb4042b04aaac58533daf33d72cdded68e3f2ca7471e094c7639d34364736f6c63430008160033";

type AppAuthConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: AppAuthConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class AppAuth__factory extends ContractFactory {
  constructor(...args: AppAuthConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override getDeployTransaction(
    overrides?: NonPayableOverrides & { from?: string }
  ): Promise<ContractDeployTransaction> {
    return super.getDeployTransaction(overrides || {});
  }
  override deploy(overrides?: NonPayableOverrides & { from?: string }) {
    return super.deploy(overrides || {}) as Promise<
      AppAuth & {
        deploymentTransaction(): ContractTransactionResponse;
      }
    >;
  }
  override connect(runner: ContractRunner | null): AppAuth__factory {
    return super.connect(runner) as AppAuth__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): AppAuthInterface {
    return new Interface(_abi) as AppAuthInterface;
  }
  static connect(address: string, runner?: ContractRunner | null): AppAuth {
    return new Contract(address, _abi, runner) as unknown as AppAuth;
  }
}
