import { ethers, keccak256 } from "ethers";
import { UserOperation, PackedUserOperation } from "../interface/UserOperation.js"
import { packUserOp as userOp2PackedUserOp } from "./convert.js";

// Constants for EIP-712
const DOMAIN_NAME = 'ERC4337';
const DOMAIN_VERSION = '1';
const USER_OP_TYPE = 'PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)';
const EIP712_DOMAIN_TYPE = 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)';

/**
 * pack a PackedUserOperation into a string.
 *
 * @export
 * @param {PackedUserOperation} packedOp
 * @return {*}  {string}
 */
export function packUserOp(packedOp: PackedUserOperation): string {
    const abiCoder = new ethers.AbiCoder();
    return abiCoder.encode(
        [
            'address', 'uint256', 'bytes32', 'bytes32',
            'bytes32', 'uint256', 'bytes32', 'bytes32'
        ],
        [
            packedOp.sender,
            packedOp.nonce,
            keccak256(packedOp.initCode),
            keccak256(packedOp.callData),
            packedOp.accountGasLimits,
            packedOp.preVerificationGas,
            packedOp.gasFees,
            keccak256(packedOp.paymasterAndData)
        ]
    );
}

/**
 * Calculate the EIP-712 domain separator
 * @param entryPoint The EntryPoint contract address
 * @param chainId The chain ID
 * @returns The domain separator hash
 */
function getDomainSeparator(entryPoint: string, chainId: number): string {
    const domainSeparator = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
            ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
            [
                ethers.keccak256(ethers.toUtf8Bytes(EIP712_DOMAIN_TYPE)),
                ethers.keccak256(ethers.toUtf8Bytes(DOMAIN_NAME)),
                ethers.keccak256(ethers.toUtf8Bytes(DOMAIN_VERSION)),
                chainId,
                entryPoint
            ]
        )
    );
    return domainSeparator;
}

/**
 * Hash the packed user operation according to EIP-712
 * @param packedUserOp The packed user operation
 * @returns The operation hash
 */
function hashPackedUserOp(packedUserOp: PackedUserOperation): string {
    // Encode each field according to EIP-712
    const encodedData = ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes32', 'address', 'uint256', 'bytes32', 'bytes32', 'bytes32', 'uint256', 'bytes32', 'bytes32'],
        [
            ethers.keccak256(ethers.toUtf8Bytes(USER_OP_TYPE)),
            packedUserOp.sender,
            packedUserOp.nonce,
            ethers.keccak256(packedUserOp.initCode),
            ethers.keccak256(packedUserOp.callData),
            packedUserOp.accountGasLimits,
            packedUserOp.preVerificationGas,
            packedUserOp.gasFees,
            ethers.keccak256(packedUserOp.paymasterAndData)
        ]
    );

    return ethers.keccak256(encodedData);
}

/**
 * calculate the userOpHash of a given userOperation.
 * The userOpHash is a hash of all UserOperation fields, except the "signature" field.
 * The entryPoint uses this value in the emitted UserOperationEvent.
 * A wallet may use this value as the hash to sign (the SampleWallet uses this method)
 * Implementation for EntryPoint v0.8 with EIP-712 support.
 * @param op UserOperation or PackedUserOperation
 * @param entryPoint EntryPoint contract address
 * @param chainId Chain ID
 */
export function getUserOpHash(op: UserOperation | PackedUserOperation, entryPoint: string, chainId: number): string {
    let packedOp: PackedUserOperation;
    if ('verificationGasLimit' in op) {
        packedOp = userOp2PackedUserOp(op as UserOperation);
    } else {
        packedOp = op as PackedUserOperation;
    }

    // Get domain separator
    const domainSeparator = getDomainSeparator(entryPoint, chainId);

    // Hash the operation data
    const opHash = hashPackedUserOp(packedOp);

    // Combine as per EIP-712: \x19\x01 + domainSeparator + hashStruct
    const encodedData = ethers.solidityPacked(
        ['string', 'bytes32', 'bytes32'],
        ['\x19\x01', domainSeparator, opHash]
    );

    return ethers.keccak256(encodedData);
}