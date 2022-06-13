use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub mod util;
pub mod arp;
pub mod tls;
pub mod quic;
pub mod sink;
pub mod engine;

mod commands;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    command: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    Spoof {
        /// The target IP address to spoof
        #[clap(short, long)]
        target: String,

        /// The interface to use, defaults to the first one found
        #[clap(short, long)]
        gateway: Option<String>,

        /// The interface to use
        #[clap(short, long)]
        interface: String,

        /// The lua file to interpret
        #[clap(short, long)]
        file: Option<PathBuf>,

        /// Capture all traffic instead of just traffic between the gateway and the target
        #[clap(short, long)]
        all: bool
    },
    Inspect {
        #[clap(short, long)]
        file: PathBuf,

        #[clap(short, long)]
        interface: String
    }
}



#[macro_use]
extern crate log;

fn main() {
    pretty_env_logger::init();

    let args = Args::parse();

    match args.command {
        Commands::Spoof { .. } => {
            commands::spoof::run(args);
        },
        Commands::Inspect { .. } => {
            commands::inspect::run(args);
        }
    }

}


