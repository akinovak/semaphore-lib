const { groth16 } = require('snarkjs');
import BaseSemaphore from './base';
import { poseidonHash, SNARK_FIELD_SIZE } from './common';
import { Identity, IncrementalQuinTree, IProof, IWitnessData } from './types';
const Tree = require('incrementalquintree/build/IncrementalQuinTree');
import * as bigintConversion from 'bigint-conversion';
const ZqField = require('ffjavascript').ZqField;
const Fq = new ZqField(SNARK_FIELD_SIZE);

class RLN extends BaseSemaphore {

    calculateIdentitySecret(identity: Identity): bigint {
        const identitySecret: bigint = bigintConversion.bufToBigint(identity.keypair.privKey); 
        return Fq.normalize(identitySecret);
    }

    calculateA1(identity: Identity, epoch: string) {
        const identitySecret: bigint = this.calculateIdentitySecret(identity);
        return poseidonHash([identitySecret, BigInt(epoch)])
    }
    
    calculateY(a1:bigint, identity: Identity, signalHash: bigint): bigint {
        const identitySecret: bigint = this.calculateIdentitySecret(identity);
        return Fq.normalize(a1 * signalHash + identitySecret);
    }

    genNullifier(a1: bigint): bigint {
        return poseidonHash([a1]);
    }

    retrievePrivateKey(x1: bigint, x2:bigint, y1:bigint, y2:bigint) {
        const slope = Fq.div(Fq.sub(y2, y1), Fq.sub(x2, x1))
        return Fq.sub(y1, Fq.mul(slope, x1));
    }

    genIdentityCommitment(identity: Identity): bigint {
        if(!this.commitmentHasher) throw new Error('Hasher not set');
        const identitySecret: bigint = this.calculateIdentitySecret(identity);
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

            const identitySecret: bigint = this.calculateIdentitySecret(identity);

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