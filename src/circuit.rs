use itertools::Itertools;
use phantom_zone::*;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, FheBool, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};
use rand::{thread_rng, RngCore};

use crate::{Cipher, FheUint8, ServerKeyShare};

/// Circuit
pub(crate) fn sum_fhe_dyn(receving_karmas: &[FheUint8], given_out: &FheUint8) -> FheUint8 {
    let sum: FheUint8 = receving_karmas
        .iter()
        .cloned()
        .reduce(|a, b| &a + &b)
        .expect("At least one input is received");
    &sum - given_out
}

const BOARD_SIZE: usize = 4;

#[derive(Clone)]
struct Board {
    eggs: [FheBool; BOARD_SIZE],
    // user_positions : Vec<(FheBool, FheBool)>
}

// This is tech debt.
// This is doing nothing, but when fantom-zone has set-constant,
// we will allow clients to call this.
pub(crate) fn init_state(tile: &Board) -> Board {
    tile.clone()
}

fn not(x: &FheBool) -> FheBool {
    !x
}

pub(crate) fn select(tile: &Board, coord: &(FheBool, FheBool)) -> FheBool {
    let x = &coord.0;
    let y = &coord.1;

    // (0,0)
    let cond_1 = &(&not(x) & &not(y)) & &tile.eggs[0];
    // (0,1)
    let cond_2 = &(&not(x) & &y) & &tile.eggs[1];
    // (1,0)
    let cond_3 = &(x & &not(y)) & &tile.eggs[2];
    // (1,1)
    let cond_4 = &(x & &y) & &tile.eggs[3];
    &(&(&cond_1 | &cond_2) | &cond_3) | &cond_4
}

// pub(crate) fn select2(
//     tile: &Board,
//     encrypted_zero: FheUint8,
//     encrypted_one: FheUint8,
//     coord: &(FheUint8, FheUint8),
//     board_coords: &[(FheUint8, FheUint8); 400],
// ) -> FheUint8 {
//     let (x, y) = coord;

//     let mut result = encrypted_zero;

//     for i in 0..400 {
//         let (x_value, y_value) = &board_coords[i];
//         let x_match = x.eq(x_value);
//         let y_match = y.eq(y_value);
//         let coord_match = &x_match & &y_match;

//         let masked_value = coord_match.if_then_else(&tile.eggs[i], &encrypted_zero);

//         result = result + masked_value;
//     }

//     result
// }

pub(crate) fn set_fhe_square(tile: &mut Board, coord: &(FheBool, FheBool)) {
    // Select the board value corresponding to the coordinate
    let selected_value = select(tile, coord);
    // Flip the value
    let flipped_value = not(&selected_value);

    // Now replace the value on the board

    // (0,0)
    let tile_was_0_0 = is_equal(coord, (false, false));
    tile.eggs[0] = &(&tile_was_0_0 & &flipped_value) | &(&not(&tile_was_0_0) & &tile.eggs[0]);

    // (0,1)
    let tile_was_0_1 = is_equal(coord, (false, true));
    tile.eggs[1] = &(&tile_was_0_1 & &flipped_value) | &(&not(&tile_was_0_1) & &tile.eggs[1]);

    // (1,0)
    let tile_was_1_0 = is_equal(coord, (true, false));
    tile.eggs[2] = &(&tile_was_1_0 & &flipped_value) | &(&not(&tile_was_1_0) & &tile.eggs[2]);

    // (1,1)
    let tile_was_1_1 = is_equal(coord, (true, true));
    tile.eggs[3] = &(&tile_was_1_1 & &flipped_value) | &(&not(&tile_was_1_1) & &tile.eggs[3]);
}

fn is_equal(coord: &(FheBool, FheBool), coord2: (bool, bool)) -> FheBool {
    let x = &coord.0;
    let y = &coord.1;
    match coord2 {
        (true, true) => (x & &y),
        (true, false) => (x & &not(y)),
        (false, true) => (&not(x) & &y),
        (false, false) => (&not(x) & &not(y)),
    }
}

#[test]
fn test_boolean_square_demo() {
    // The number of people in the MPC computation
    //
    // This should be parametrizable by the number of parties
    set_parameter_set(ParameterSelector::NonInteractiveLTE2Party);

    // Set the common reference string for interaction
    //
    // The server picks this and send to all clients
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    set_common_reference_seed(seed);

    let parties = 2;

    let cks = (0..parties).map(|_| gen_client_key()).collect_vec();

    // Each client generates a key share for the server
    //
    // The server will aggregate these to get the server key
    let s_key_shares = cks
        .iter()
        .enumerate()
        .map(|(user_id, k)| gen_server_key_share(user_id, parties, k))
        .collect_vec();

    // Server key is used for bootstrapping
    let server_key = aggregate_server_key_shares(&s_key_shares);
    server_key.set_server_key();

    // Set the initial state
    let c0 = cks[0].encrypt(vec![false; BOARD_SIZE].as_slice());

    // Server does key switch on client ciphertext to make it possible
    // to do fhe operations on them
    //
    // Server needs to know which user has given them what cipher text
    let board_state = c0.unseed::<Vec<Vec<u64>>>().key_switch(0).extract_all();
    let eggs: [FheBool; BOARD_SIZE] = match board_state.try_into() {
        Ok(x) => x,
        Err(_) => panic!("board state size incorrect"),
    };
    let mut board = Board { eggs };

    // Client 1 encrypts (0,0) and sends that to the server to change
    let c1 = cks[1].encrypt(vec![false, false].as_slice());
    let coord = {
        let mut tmp = c1.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_all();
        (tmp.swap_remove(0), tmp.swap_remove(0))
    };

    // Server to change a value on the board
    set_fhe_square(&mut board, &coord);

    let c1 = cks[1].encrypt(vec![false, true].as_slice());
    let coord = {
        let mut tmp = c1.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_all();
        (tmp.swap_remove(0), tmp.swap_remove(0))
    };

    // Server to change a value on the board
    set_fhe_square(&mut board, &coord);

    // Each client generates a decryption share for the output received
    // from the server
    let mut vec_dec_shares = Vec::new();
    for state_element in board.eggs.clone() {
        let dec_shares = cks
            .iter()
            .map(|k| k.gen_decryption_share(&state_element))
            .collect_vec();

        vec_dec_shares.push(dec_shares);
    }

    let mut unencrypted_board = Vec::new();
    for (dec_shares, enc_out) in vec_dec_shares.iter().zip(board.eggs.iter()) {
        unencrypted_board.push(cks[0].aggregate_decryption_shares(enc_out, dec_shares));
    }

    dbg!(unencrypted_board);
}
