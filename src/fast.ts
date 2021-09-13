const { groth16 } = require('snarkjs');
import BaseSemaphore from './base';
import { identityCommitmentHasher, poseidonHash } from './common';
import { Identity, IncrementalQuinTree, IProof, IWitnessData } from './types';
const Tree = require('incrementalquintree/build/IncrementalQuinTree');

class FastSemaphore extends BaseSemaphore {
    genIdentityCommitment(identity: Identity, hasher: string): bigint {

        const hash = identityCommitmentHasher[hasher];
        if (!hash) throw new Error(`${hasher} identityCommitment hasher not provided`);

        const data = [identity.identityNullifier, identity.identityTrapdoor];
        return hash(data);
    }

    async genProofFromIdentityCommitments(identity: Identity, 
        externalNullifier: string | bigint, 
        signal: string, 
        identityCommitmentHasher: string,
        wasmFilePath: string, 
        finalZkeyPath: string, 
        identityCommitments: Array<BigInt>, 
        depth: number, zeroValue: BigInt, 
        leavesPerNode: number): Promise<IWitnessData> {

        const tree: IncrementalQuinTree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, poseidonHash);
        const identityCommitment: BigInt = this.genIdentityCommitment(identity, identityCommitmentHasher);
        const leafIndex = identityCommitments.indexOf(identityCommitment);
        if(leafIndex === -1) throw new Error('This commitment is not registered');
        
        for(const identityCommitment of identityCommitments) {
            tree.insert(identityCommitment);
        }

        console.log('leaf index', leafIndex);
        const merkleProof = tree.genMerklePath(leafIndex);
        
        const fullProof: IProof = await this.genProofFromBuiltTree(identity, merkleProof, externalNullifier, signal, wasmFilePath, finalZkeyPath);
        return {
            fullProof, 
            root: tree.root
        }
    }

    //sometimes identityCommitments array can be to big so we must generate it on server and just use it on frontend
    async genProofFromBuiltTree(identity: Identity, merkleProof: any, externalNullifier: string | bigint, signal: string, 
        wasmFilePath: string, finalZkeyPath: string): Promise<IProof> {

        const grothInput: any = {
            identity_nullifier: identity.identityNullifier,
            identity_trapdoor: identity.identityTrapdoor,
            identity_path_index: merkleProof.indices,
            path_elements: merkleProof.pathElements,
            external_nullifier: externalNullifier,
            signal_hash: this.genSignalHash(signal),
        }

        return groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath);
    }

}

export default new FastSemaphore();