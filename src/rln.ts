const { groth16 } = require('snarkjs');
import BaseSemaphore from './base';
import { poseidonHash, SNARK_FIELD_SIZE } from './common';
import { Identity, IncrementalQuinTree, IProof, IWitnessData } from './types';
const Tree = require('incrementalquintree/build/IncrementalQuinTree');
import * as bigintConversion from 'bigint-conversion';
const ZqField = require('ffjavascript').ZqField;
const Fq = new ZqField(SNARK_FIELD_SIZE);

class RLN extends BaseSemaphore {

    calculateIdentitySecret(privateKey: Buffer): bigint {
        const identitySecret: bigint = bigintConversion.bufToBigint(privateKey); 
        return Fq.normalize(identitySecret);
    }

    calculateA1(privateKey: Buffer, epoch: string) {
        const identitySecret: bigint = this.calculateIdentitySecret(privateKey);
        return poseidonHash([identitySecret, BigInt(epoch)])
    }
    
    calculateY(a1:bigint, privateKey: Buffer, signalHash: bigint): bigint {
        const identitySecret: bigint = this.calculateIdentitySecret(privateKey);
        return Fq.normalize(a1 * signalHash + identitySecret);
    }

    genNullifier(a1: bigint): bigint {
        return poseidonHash([a1]);
    }

    retrievePrivateKey(x1: bigint, x2:bigint, y1:bigint, y2:bigint): bigint {
        const slope = Fq.div(Fq.sub(y2, y1), Fq.sub(x2, x1))
        const privateKey = Fq.sub(y1, Fq.mul(slope, x1));
        return Fq.normalize(privateKey);
    }

    genIdentityCommitment(privateKey: Buffer): bigint {
        if(!this.commitmentHasher) throw new Error('Hasher not set');
        const identitySecret: bigint = this.calculateIdentitySecret(privateKey);
        const data = [identitySecret];
        return this.commitmentHasher(data);
    }


    async genProofFromIdentityCommitments(privateKey: Buffer, 
        epoch: string | bigint, 
        signal: string, 
        wasmFilePath: string, 
        finalZkeyPath: string, 
        identityCommitments: Array<BigInt>, 
        depth: number, zeroValue: BigInt, 
        leavesPerNode: number): Promise<IWitnessData> {

        const tree: IncrementalQuinTree = new Tree.IncrementalQuinTree(depth, zeroValue, leavesPerNode, poseidonHash);
        const identityCommitment: BigInt = this.genIdentityCommitment(privateKey);
        const leafIndex = identityCommitments.indexOf(identityCommitment);
        if(leafIndex === -1) throw new Error('This commitment is not registered');
        
        for(const identityCommitment of identityCommitments) {
            tree.insert(identityCommitment);
        }

        const merkleProof = tree.genMerklePath(leafIndex);
        
        const fullProof: IProof = await this.genProofFromBuiltTree(privateKey, merkleProof, epoch, signal, wasmFilePath, finalZkeyPath);
        return {
            fullProof, 
            root: tree.root
        }
    }

    //sometimes identityCommitments array can be to big so we must generate it on server and just use it on frontend
    async genProofFromBuiltTree(privateKey: Buffer, merkleProof: any, epoch: string | bigint, signal: string, 
        wasmFilePath: string, finalZkeyPath: string): Promise<IProof> {

            const identitySecret: bigint = this.calculateIdentitySecret(privateKey);

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