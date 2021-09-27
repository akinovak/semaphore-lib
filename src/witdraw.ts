const { groth16 } = require('snarkjs');
import BaseSemaphore from './base';
import { poseidonHash } from './common';
import { Identity, IncrementalQuinTree, IProof, IWitnessData } from './types';
const Tree = require('incrementalquintree/build/IncrementalQuinTree');

class Witdraw {

    genNullifierHash = (nullifier: bigint): bigint => {
        return poseidonHash([nullifier])
    }


    //sometimes identityCommitments array can be to big so we must generate it on server and just use it on frontend
    async genProofFromBuiltTree(noteSecret, nullifier, merkleProof, wasmFilePath, finalZkeyPath): Promise<IProof> {


            const grothInput: any = {
                note_secret: noteSecret,
                nullifier,
                path_elements: merkleProof.pathElements,
                path_indices: merkleProof.indices,
            }

        return groth16.fullProve(grothInput, wasmFilePath, finalZkeyPath);
    }
    

}

export default new Witdraw();