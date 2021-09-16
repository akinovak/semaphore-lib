const { groth16 } = require('snarkjs');
import BaseSemaphore from './base';
import { poseidonHash, SNARK_FIELD_SIZE } from './common';
import { Identity, IncrementalQuinTree, IProof, IWitnessData } from './types';
const Tree = require('incrementalquintree/build/IncrementalQuinTree');
import * as bigintConversion from 'bigint-conversion';

class RLN extends BaseSemaphore {
    calculateA1(identity: Identity, epoch: string) {
        const identitySecret: bigint = bigintConversion.bufToBigint(identity.keypair.privKey);
        return poseidonHash([identitySecret, BigInt(epoch)])
    }
    
    calculateY(a1:bigint, identity: Identity, signalHash: bigint): bigint {
        const identitySecret: bigint = bigintConversion.bufToBigint(identity.keypair.privKey);
        return (a1 * signalHash + identitySecret) % SNARK_FIELD_SIZE;
    }

    genNullifier(a1: bigint): bigint {
        return poseidonHash([a1]);
    }

    genIdentityCommitment(identity: Identity): bigint {
        if(!this.commitmentHasher) throw new Error('Hasher not set');
        const identitySecret: bigint = bigintConversion.bufToBigint(identity.keypair.privKey);
        const data = [identitySecret];
        return this.commitmentHasher(data);
    }

    async genProofFromIdentityCommitments(identity: Identity, 
        epoch: string | bigint, 
        signal: string, 
        wasmFilePath: string, 
        finalZkeyPath: string, 
        identityCommitments: Array<BigInt>, 
        depth: number, zeroValue: BigInt, 
        leavesPerNode: number): Promise<IWitnessData> {

        const tree: IncrementalQuinTree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, poseidonHash);
        const identityCommitment: BigInt = this.genIdentityCommitment(identity);
        const leafIndex = identityCommitments.indexOf(identityCommitment);
        if(leafIndex === -1) throw new Error('This commitment is not registered');
        
        for(const identityCommitment of identityCommitments) {
            tree.insert(identityCommitment);
        }

        const merkleProof = tree.genMerklePath(leafIndex);
        
        const fullProof: IProof = await this.genProofFromBuiltTree(identity, merkleProof, epoch, signal, wasmFilePath, finalZkeyPath);
        return {
            fullProof, 
            root: tree.root
        }
    }

    //sometimes identityCommitments array can be to big so we must generate it on server and just use it on frontend
    async genProofFromBuiltTree(identity: Identity, merkleProof: any, epoch: string | bigint, signal: string, 
        wasmFilePath: string, finalZkeyPath: string): Promise<IProof> {

            const identitySecret: bigint = bigintConversion.bufToBigint(identity.keypair.privKey);

            const grothInput: any = {
                identity_secret: identitySecret,
                path_elements: merkleProof.pathElements,
                identity_path_index: merkleProof.indices,
                epoch,
                x: this.genSignalHash(signal),
            }

        return groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath);
    }

}

export default new RLN();