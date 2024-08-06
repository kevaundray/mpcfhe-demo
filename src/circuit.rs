use itertools::Itertools;
use phantom_zone::*;
use phantom_zone::{
    aggregate_server_key_shares, set_parameter_set, FheBool, KeySwitchWithId, ParameterSelector,
    SampleExtractor,
};
use rand::{thread_rng, RngCore};
use rayon::prelude::*;

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

pub(crate) fn update_egg(
    tile: &Board,
    coord: &(FheUint8, FheUint8),
    board_coords: &[(FheUint8, FheUint8); BOARD_SIZE],
    max_coord: &FheUint8,
    new_value: &FheUint8,
) -> Board {
    let (x, y) = coord;
    // Check if x and y are within bounds
    // let x_in_bounds = x.le(max_coord);
    // let y_in_bounds = y.le(max_coord);
    // let in_bounds = &x_in_bounds & &y_in_bounds;

    // Create a new Board with updated eggs
    let updated_eggs: Vec<FheUint8> = (0..BOARD_SIZE)
        .into_par_iter()
        .map(|i| {
            let (x_value, y_value) = &board_coords[i];
            let x_match = x.eq(x_value);
            let y_match = y.eq(y_value);
            let coord_match = &x_match & &y_match;
            // Only update if coordinates are in bounds
            // TODO: We should not need to inverse this condition here, investigate
            let safe_coord_match = !&(coord_match);

            // Update the egg with the new value if it matches the coordinates
            tile.eggs[i].mux(new_value, &safe_coord_match)
        })
        .collect();

    Board {
        eggs: updated_eggs.try_into().unwrap(),
    }
}

// This is the length and width of the board
// It will always be a square.
// we choose 20 to make the board small and also because
// we currently only have FheUINT8, so each coordinate
// must fit within a u8
const BOARD_DIMS: u8 = 2;
const BOARD_SIZE: usize = (BOARD_DIMS as usize) * (BOARD_DIMS as usize);

const NUM_PLAYERS: usize = 2;

pub struct Server {
    max_coord: ConstFheUint8,

    encrypted_false: FheBool,
    encrypted_true: FheBool,

    encrypted_zero: ConstFheUint8,
    encrypted_one: ConstFheUint8,
    encrypted_two: ConstFheUint8,
    encrypted_three: ConstFheUint8,

    player_tokens: [Option<FheUint8>; NUM_PLAYERS],
    player_coords: [Option<(FheUint8, FheUint8)>; NUM_PLAYERS],

    board: Board,
    board_coords: [(ConstFheUint8, ConstFheUint8); BOARD_SIZE],
}

// Since we do not have access to ciphertext constants (right now)
// We need one of the clients to encrypt the constants for us
// to setup the board and to store encrypted constants that the
// server will need.
pub fn setup_values(client_key: ClientKey) -> EncryptedU8Values {
    const NUMBERS_NEEDED_TO_ENCODE_DIRECTIONS: u8 = 4;
    let range = std::cmp::max(BOARD_DIMS, NUMBERS_NEEDED_TO_ENCODE_DIRECTIONS);
    let board_dim_range: Vec<u8> = (0..range).collect();
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

        let encrypted_zero = encrypted_constants[0].clone();
        let encrypted_one = encrypted_constants[1].clone();
        let encrypted_two = encrypted_constants[2].clone();
        let encrypted_three = encrypted_constants[3].clone();
        let eggs = vec![encrypted_zero.clone(); BOARD_SIZE];

        let encrypted_true = encrypted_zero.eq(&encrypted_zero);
        let encrypted_false = encrypted_zero.eq(&encrypted_one);

        // Make the board be all zeroes as initial state
        let board = Board {
            eggs: eggs.try_into().unwrap(),
        };

        let max_coord = encrypted_constants.last().unwrap().clone();

        fn generate_coordinates(values: &[FheUint8]) -> Vec<(FheUint8, FheUint8)> {
            let mut coordinates = Vec::with_capacity(values.len() * values.len());

            for x in values.into_iter().take(BOARD_DIMS as usize) {
                for y in values.into_iter().take(BOARD_DIMS as usize) {
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
            encrypted_false,
            encrypted_true,
            encrypted_zero,
            encrypted_one,
            encrypted_two,
            encrypted_three,
            board_coords,
            player_tokens: Default::default(),
            player_coords: Default::default(),
        }
    }

    pub(crate) fn set_player(
        &mut self,
        player_id: usize,
        token: FheUint8,
        coords: (FheUint8, FheUint8),
    ) {
        // TODO: We should error when the player token is already set
        self.player_tokens[player_id] = Some(token);
        self.player_coords[player_id] = Some(coords);
    }

    fn check_all_players_ready(&self) -> bool {
        for token in &self.player_tokens {
            if token.is_none() {
                return false;
            }
        }
        true
    }
    pub(crate) fn set_fhe_square(&mut self, coord: &(FheUint8, FheUint8), new_value: FheUint8) {
        // check if all of the players are ready
        assert!(self.check_all_players_ready());

        let new_board = update_egg(
            &self.board,
            coord,
            &self.board_coords,
            &self.max_coord,
            &new_value,
        );

        self.board = new_board;
    }

    // 0 => UP
    // 1 => down
    // 2 => Left
    // 3 => right
    pub(crate) fn move_direction(
        &mut self,
        player_id: usize,
        token: &FheUint8,
        direction: &FheUint8,
    ) -> ((FheUint8, FheUint8), FheBool) {
        // We return a 1 to indicate an error
        if player_id >= self.player_tokens.len() {
            return (
                (self.encrypted_zero.clone(), self.encrypted_zero.clone()),
                self.encrypted_false.clone(),
            );
        }

        // Get the current player's coordinate which is x and y
        let (current_x, current_y) = self.player_coords[player_id].clone().unwrap();
        // Get the player's auth token
        let player_token = self.player_tokens[player_id].clone().unwrap();

        // Create encrypted constants
        let zero = &self.encrypted_zero;
        let one = &self.encrypted_one;
        let two = &self.encrypted_two;
        let three = &self.encrypted_three;
        let board_size = &self.max_coord + &self.encrypted_one;

        // Calculate new coordinates based on direction
        let up = direction.eq(zero);
        let down = direction.eq(one);
        let left = direction.eq(two);
        let right = direction.eq(three);

        // Calculate new x coordinate with wrapping
        //
        // TODO: Optimize modulo operation by replacing it with a mux, plus an addition.
        // TODO: Since we know that the value will only be one multiple of board_size away from the
        // TODO: canonical range
        let x_minus_one = &(&current_x - one);
        let x_plus_one = &(&current_x + one);
        let new_x = &current_x.mux(&x_minus_one, &left).mux(&x_plus_one, &right);
        let new_x_reduced = new_x % &board_size;

        // Calculate new y coordinate with wrapping
        let y_minus_one = &(&current_y - one);
        let y_plus_one = &(&current_y + one);
        let new_y = &current_y.mux(&y_minus_one, &up).mux(&y_plus_one, &down);
        let new_y_reduced = new_y % &board_size;

        // Check if the provided token matches the player's token
        let token_match = token.eq(&player_token);

        // Update the player's coordinates only if the token matches
        let final_x = current_x.mux(&new_x_reduced, &token_match);
        let final_y = current_y.mux(&new_y_reduced, &token_match);

        self.player_coords[player_id] = Some((final_x.clone(), final_y.clone()));

        // Return the new coordinates and true if the token matched, or the old coordinates and false if it didn't
        ((final_x, final_y), token_match)
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

    let parties = NUM_PLAYERS;

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
    //
    // These are values from 0 to BOARD_DIMS - 1
    const PARTY_WHO_ENCRYPTED_CONSTANTS: usize = 0;
    let encrypted_constants = setup_values(cks[PARTY_WHO_ENCRYPTED_CONSTANTS].clone());
    // Setup server with initial state
    let mut server = Server::new(encrypted_constants, PARTY_WHO_ENCRYPTED_CONSTANTS);

    // Each player needs to set their own coords and token values
    // We assume players are choosing this randomly
    //
    //
    let token_values = vec![123u8, 245u8];
    let starting_coords = vec![(0u8, 1u8), (1u8, 0u8)];
    let mut encrypted_token_values = Vec::new();

    for player_index in 0..NUM_PLAYERS {
        let client_key = &cks[player_index];
        let token = token_values[player_index];
        let client_encrypted_token = client_key.encrypt(vec![token].as_slice());

        let encrypted_token = {
            let mut tmp = client_encrypted_token
                .unseed::<Vec<Vec<u64>>>()
                .key_switch(player_index)
                .extract_all();
            tmp.swap_remove(0)
        };

        let (x, y) = starting_coords[player_index];
        let client_encrypted_starting_coords = cks[player_index].encrypt(vec![x, y].as_slice());
        let (encrypted_x, encrypted_y) = {
            let mut tmp = client_encrypted_starting_coords
                .unseed::<Vec<Vec<u64>>>()
                .key_switch(player_index)
                .extract_all();
            (tmp.swap_remove(0), tmp.swap_remove(0))
        };
        encrypted_token_values.push(encrypted_token.clone());

        server.set_player(player_index, encrypted_token, (encrypted_x, encrypted_y))
    }

    // Now lets move this player UP which is encoded as 0
    let client_encrypted_move = cks[0].encrypt(vec![0u8].as_slice());

    // Server now needs to key switch
    let encrypted_move = {
        let mut tmp = client_encrypted_move
            .unseed::<Vec<Vec<u64>>>()
            .key_switch(1)
            .extract_all();
        tmp.swap_remove(0)
    };

    rayon::ThreadPoolBuilder::new()
        .build_scoped(
            // Initialize thread-local storage parameters
            |thread| {
                set_parameter_set(ParameterSelector::NonInteractiveLTE2Party);
                thread.run()
            },
            // Run parallel code under this pool
            |pool| {
                pool.install(|| {
                    server.move_direction(0, &encrypted_token_values[0], &encrypted_move)
                })
            },
        )
        .unwrap();

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
    let mut vec_dec_shares = Vec::new();
    for state_element in server.board.eggs.clone() {
        let dec_shares = cks
            .iter()
            .map(|k| k.gen_decryption_share(&state_element))
            .collect_vec();

        vec_dec_shares.push(dec_shares);
    }

    let mut unencrypted_board = Vec::new();
    for (dec_shares, enc_out) in vec_dec_shares.iter().zip(server.board.eggs.iter()) {
        unencrypted_board.push(cks[0].aggregate_decryption_shares(enc_out, dec_shares));
    }

    dbg!(unencrypted_board);
}
