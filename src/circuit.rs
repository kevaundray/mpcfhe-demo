use itertools::Itertools;
use phantom_zone::*;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, FheBool, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};
use rand::{thread_rng, RngCore};

use crate::types::{ConstFheUint8, EncryptedU8Values};
use crate::{Cipher, FheUint8, ServerKeyShare};

#[derive(Clone)]
struct Board {
    eggs: [FheUint8; BOARD_SIZE],
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

pub(crate) fn select2(
    tile: &Board,
    encrypted_zero: &FheUint8,
    coord: &(FheUint8, FheUint8),
    board_coords: &[(FheUint8, FheUint8); BOARD_SIZE],
    max_coord: &FheUint8, // Maximum allowed coordinate value (e.g., 19 for a 20x20 board)
) -> FheUint8 {
    let (x, y) = coord;
    let mut result = encrypted_zero.clone();

    // Check if x and y are within bounds
    let x_in_bounds = x.le(&max_coord);
    let y_in_bounds = y.le(&max_coord);
    let in_bounds = &x_in_bounds & &y_in_bounds;

    for i in 0..BOARD_SIZE {
        let (x_value, y_value) = &board_coords[i];
        let x_match = x.eq(x_value);
        let y_match = y.eq(y_value);
        let coord_match = &x_match & &y_match;

        // Only select if coordinates are in bounds
        let safe_coord_match = &coord_match & &in_bounds;

        let masked_value = tile.eggs[i].mux(&encrypted_zero, &safe_coord_match);
        result = &result + &masked_value;
    }
    result
}

// This is the length and width of the board
// It will always be a square.
// we choose 20 to make the board small and also because
// we currently only have FheUINT8, so each coordinate
// must fit within a u8
const BOARD_DIMS: u8 = 20;
const BOARD_SIZE: usize = (BOARD_DIMS as usize) * (BOARD_DIMS as usize);

pub struct Server {
    max_coord: ConstFheUint8,
    encrypted_zero: ConstFheUint8,

    board: Board,
    board_coords: [(ConstFheUint8, ConstFheUint8); BOARD_SIZE],
}

// Since we do not have access to ciphertext constants (right now)
// We need one of the clients to encrypt the constants for us
// to setup the board and to store encrypted constants that the
// server will need.
pub fn setup_values(client_key: ClientKey) -> EncryptedU8Values {
    let board_dim_range: Vec<u8> = (0..BOARD_DIMS).collect();
    client_key.encrypt(board_dim_range.as_slice())
}

impl Server {
    fn new(
        encrypted_coord_range: EncryptedU8Values,
        party_who_encrypted_constants: usize,
    ) -> Server {
        let encrypted_constants = encrypted_coord_range
            .unseed::<Vec<Vec<u64>>>()
            .key_switch(party_who_encrypted_constants)
            .extract_all();

        // We should have BOARD_DIMS number of encrypted constants
        let encrypted_constants: [FheUint8; BOARD_DIMS as usize] =
            encrypted_constants.try_into().unwrap();

        let encrypted_zero = encrypted_constants[0].clone();
        let eggs = vec![encrypted_zero.clone(); BOARD_SIZE];

        // Make the board be all zeroes as initial state
        let board = Board {
            eggs: eggs.try_into().unwrap(),
        };

        let max_coord = encrypted_constants.last().unwrap().clone();

        fn generate_coordinates(values: &[FheUint8]) -> Vec<(FheUint8, FheUint8)> {
            let mut coordinates = Vec::with_capacity(values.len() * values.len());

            for x in values {
                for y in values {
                    coordinates.push((x.clone(), y.clone()));
                }
            }

            coordinates
        }
        let board_coords = generate_coordinates(&encrypted_constants)
            .try_into()
            .unwrap();

        Server {
            max_coord,
            board,
            encrypted_zero,
            board_coords,
        }
    }
    pub(crate) fn set_fhe_square(&self, coord: &(FheUint8, FheUint8)) {
        select2(
            &self.board,
            &self.encrypted_zero,
            coord,
            &self.board_coords,
            &self.max_coord,
        );
    }
}

#[test]
fn test_uint8_square_demo() {
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
    // These are values from 0 to BOARD_DIMS - 1
    const PARTY_WHO_ENCRYPTED_CONSTANTS: usize = 0;
    let encrypted_constants = setup_values(cks[PARTY_WHO_ENCRYPTED_CONSTANTS].clone());
    // Setup server with initial state
    let server = Server::new(encrypted_constants, PARTY_WHO_ENCRYPTED_CONSTANTS);

    // Now lets set a value in the first quadrant
    let client_encrypted_coord = cks[1].encrypt(vec![0u8, 0u8].as_slice());

    // Server now needs to key switch
    let encrypted_coord = {
        let mut tmp = client_encrypted_coord
            .unseed::<Vec<Vec<u64>>>()
            .key_switch(1)
            .extract_all();
        (tmp.swap_remove(0), tmp.swap_remove(0))
    };

    server.set_fhe_square(&encrypted_coord);

    // // Server does key switch on client ciphertext to make it possible
    // // to do fhe operations on them
    // //
    // // Server needs to know which user has given them what cipher text
    // let board_state = c0.unseed::<Vec<Vec<u64>>>().key_switch(0).extract_all();
    // let eggs: [FheBool; BOARD_SIZE] = match board_state.try_into() {
    //     Ok(x) => x,
    //     Err(_) => panic!("board state size incorrect"),
    // };
    // let mut board = Board { eggs };

    // // Client 1 encrypts (0,0) and sends that to the server to change
    // let c1 = cks[1].encrypt(vec![false, false].as_slice());
    // let coord = {
    //     let mut tmp = c1.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_all();
    //     (tmp.swap_remove(0), tmp.swap_remove(0))
    // };

    // // Server to change a value on the board
    // set_fhe_square(&mut board, &coord);

    // let c1 = cks[1].encrypt(vec![false, true].as_slice());
    // let coord = {
    //     let mut tmp = c1.unseed::<Vec<Vec<u64>>>().key_switch(1).extract_all();
    //     (tmp.swap_remove(0), tmp.swap_remove(0))
    // };

    // // Server to change a value on the board
    // set_fhe_square(&mut board, &coord);

    // // Each client generates a decryption share for the output received
    // // from the server
    // let mut vec_dec_shares = Vec::new();
    // for state_element in board.eggs.clone() {
    //     let dec_shares = cks
    //         .iter()
    //         .map(|k| k.gen_decryption_share(&state_element))
    //         .collect_vec();

    //     vec_dec_shares.push(dec_shares);
    // }

    // let mut unencrypted_board = Vec::new();
    // for (dec_shares, enc_out) in vec_dec_shares.iter().zip(board.eggs.iter()) {
    //     unencrypted_board.push(cks[0].aggregate_decryption_shares(enc_out, dec_shares));
    // }

    // dbg!(unencrypted_board);
}
