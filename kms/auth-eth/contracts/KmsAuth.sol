// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "./IAppAuth.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract KmsAuth is
    Initializable,
    OwnableUpgradeable,
    UUPSUpgradeable,
    ERC165Upgradeable,
    IAppAuth
{
    // Struct for KMS information
    struct KmsInfo {
        bytes k256Pubkey;// K256 公钥
        bytes caPubkey;// CA 公钥
        bytes quote;// 硬件证明报告
        bytes eventlog;// 事件日志
    }

    // KMS information
    KmsInfo public kmsInfo;

    // The dstack-gateway App ID
    /// @custom:oz-renamed-from tproxyAppId
    string public gatewayAppId;

    // Struct to store App configuration
    struct AppConfig {
        bool isRegistered;// 是否已注册
        address controller;// 控制器地址（AppAuth 合约地址）
    }

    // Mapping of registered apps
    mapping(address => AppConfig) public apps;// 注册的应用

    // Mapping of allowed aggregated MR measurements for running KMS
    mapping(bytes32 => bool) public kmsAllowedAggregatedMrs;// 允许的 KMS 聚合度量

    // Mapping of allowed KMS device IDs
    mapping(bytes32 => bool) public kmsAllowedDeviceIds;// 允许的 KMS 设备 ID

    // Mapping of allowed image measurements
    mapping(bytes32 => bool) public allowedOsImages;// 允许的 OS 镜像

    // Sequence number for app IDs - per user
    mapping(address => uint256) public nextAppSequence;// 用户的下一个应用序列号

    // AppAuth implementation contract address for factory deployment
    address public appAuthImplementation;

    // Events
    event AppRegistered(address appId);
    event KmsInfoSet(bytes k256Pubkey);
    event KmsAggregatedMrAdded(bytes32 mrAggregated);
    event KmsAggregatedMrRemoved(bytes32 mrAggregated);
    event KmsDeviceAdded(bytes32 deviceId);
    event KmsDeviceRemoved(bytes32 deviceId);
    event OsImageHashAdded(bytes32 osImageHash);
    event OsImageHashRemoved(bytes32 osImageHash);
    event GatewayAppIdSet(string gatewayAppId);
    event AppAuthImplementationSet(address implementation);
    event AppDeployedViaFactory(address indexed appId, address indexed proxyAddress, address indexed deployer);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialize the contract with the owner wallet address and optionally set AppAuth implementation
    function initialize(address initialOwner, address _appAuthImplementation) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        __ERC165_init();
        
        // Set AppAuth implementation if provided
        if (_appAuthImplementation != address(0)) {
            appAuthImplementation = _appAuthImplementation;
            emit AppAuthImplementationSet(_appAuthImplementation);
        }
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     * @notice Returns true if this contract implements the interface defined by interfaceId
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return True if the contract implements `interfaceId`
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165Upgradeable, IERC165)
        returns (bool)
    {
        return
            interfaceId == 0x1e079198 || // IAppAuth
            super.supportsInterface(interfaceId);
    }

    // Function to authorize upgrades (required by UUPSUpgradeable)
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // Function to set KMS information
    function setKmsInfo(KmsInfo memory info) external onlyOwner {
        kmsInfo = info;
        emit KmsInfoSet(info.k256Pubkey);
    }

    // Function to set KMS quote
    function setKmsQuote(bytes memory quote) external onlyOwner {
        kmsInfo.quote = quote;
    }

    // Function to set KMS eventlog
    function setKmsEventlog(bytes memory eventlog) external onlyOwner {
        kmsInfo.eventlog = eventlog;
    }

    // Function to set trusted Gateway App ID
    function setGatewayAppId(string memory appId) external onlyOwner {
        gatewayAppId = appId;
        emit GatewayAppIdSet(appId);
    }

    // View next app id 预测下一个应用 ID
    function nextAppId() public view returns (address appId) {
        bytes32 fullHash = keccak256(
            abi.encodePacked(
                address(this),
                msg.sender,
                nextAppSequence[msg.sender]
            )
        );
        return address(uint160(uint256(fullHash)));
    }

    // Internal function to register an app with the given app ID and controller
    function _registerAppInternal(address appId, address controller) private {
        require(!apps[appId].isRegistered, "App already registered");
        apps[appId].isRegistered = true;
        apps[appId].controller = controller;
        nextAppSequence[msg.sender]++;
        emit AppRegistered(appId);
    }

    // Function to register an app
    function registerApp(address controller) external {
        require(controller != address(0), "Invalid controller address");
        address appId = nextAppId();
        _registerAppInternal(appId, controller);
    }

    // Function to set AppAuth implementation contract address
    function setAppAuthImplementation(address _implementation) external onlyOwner {
        require(_implementation != address(0), "Invalid implementation address");
        appAuthImplementation = _implementation;
        emit AppAuthImplementationSet(_implementation);
    }

    // Factory method: Deploy and register AppAuth in single transaction
    function deployAndRegisterApp(
        address initialOwner,
        bool disableUpgrades,
        bool allowAnyDevice,
        bytes32 initialDeviceId,
        bytes32 initialComposeHash
    ) external returns (address appId, address proxyAddress) {
        require(appAuthImplementation != address(0), "AppAuth implementation not set");
        require(initialOwner != address(0), "Invalid owner address");
        
        // Calculate app ID
        appId = nextAppId();
        
        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            bytes4(keccak256("initialize(address,address,bool,bool,bytes32,bytes32)")),
            initialOwner,
            appId,
            disableUpgrades,
            allowAnyDevice,
            initialDeviceId,
            initialComposeHash
        );
        
        // Deploy proxy contract
        proxyAddress = address(new ERC1967Proxy(appAuthImplementation, initData));
        
        // Register to KMS
        _registerAppInternal(appId, proxyAddress);
        emit AppDeployedViaFactory(appId, proxyAddress, msg.sender);
    }

    // Function to register an aggregated MR measurement
    function addKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = true;
        emit KmsAggregatedMrAdded(mrAggregated);
    }

    // Function to deregister an aggregated MR measurement
    function removeKmsAggregatedMr(bytes32 mrAggregated) external onlyOwner {
        kmsAllowedAggregatedMrs[mrAggregated] = false;
        emit KmsAggregatedMrRemoved(mrAggregated);
    }

    // Function to register a KMS device ID
    function addKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = true;
        emit KmsDeviceAdded(deviceId);
    }

    // Function to deregister a KMS device ID
    function removeKmsDevice(bytes32 deviceId) external onlyOwner {
        kmsAllowedDeviceIds[deviceId] = false;
        emit KmsDeviceRemoved(deviceId);
    }

    // Function to register an image measurement
    function addOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = true;
        emit OsImageHashAdded(osImageHash);
    }

    // Function to deregister an image measurement
    function removeOsImageHash(bytes32 osImageHash) external onlyOwner {
        allowedOsImages[osImageHash] = false;
        emit OsImageHashRemoved(osImageHash);
    }

    // Function to check if KMS is allowed to boot
    function isKmsAllowed(
        AppBootInfo calldata bootInfo
    ) external view returns (bool isAllowed, string memory reason) {
        // Check if the TCB status is up to date
        if (
            keccak256(abi.encodePacked(bootInfo.tcbStatus)) !=
            keccak256(abi.encodePacked("UpToDate"))
        ) {
            return (false, "TCB status is not up to date");
        }

        // Check if the OS image is allowed
        if (!allowedOsImages[bootInfo.osImageHash]) {
            return (false, "OS image is not allowed");
        }

        // Check if the aggregated MR is allowed
        if (!kmsAllowedAggregatedMrs[bootInfo.mrAggregated]) {
            return (false, "Aggregated MR not allowed");
        }

        // Check if the KMS device ID is allowed
        if (!kmsAllowedDeviceIds[bootInfo.deviceId]) {
            return (false, "KMS is not allowed to boot on this device");
        }

        return (true, "");
    }

    // Function to check if an app is allowed to boot
    function isAppAllowed(
        AppBootInfo calldata bootInfo
    ) external view override returns (bool isAllowed, string memory reason) {
        // Check if app is registered
        if (!apps[bootInfo.appId].isRegistered) {
            return (false, "App not registered");
        }

        // Check aggregated MR and image measurements
        if (!allowedOsImages[bootInfo.osImageHash]) {
            return (false, "OS image is not allowed");
        }

        // Ask the app controller if the app is allowed to boot
        address controller = apps[bootInfo.appId].controller;
        if (controller == address(0)) {
            return (false, "App controller not set");
        }
        return IAppAuth(controller).isAppAllowed(bootInfo);
    }

    // Add storage gap for upgradeable contracts
    uint256[50] private __gap;
}
