#![feature(format_args_capture)]

use std::{error::Error, fs::File, io::BufReader};

use gnuplot::{
    AutoOption::{Auto, Fix},
    AxesCommon, DashType, Figure, Font, LabelOption,
    PlotOption::{self, Caption, Color, LineStyle, PointSymbol},
    Tick,
};
use serde::{Deserialize, Serialize};

static SESSION_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64];
static NETWORK_SPEEDS: &[usize] = &[1, 10, 100];
static LINE_STYLES: &[PlotOption<&str>] = &[
    LineStyle(DashType::Solid),
    LineStyle(DashType::Dash),
    LineStyle(DashType::Dot),
];

static SCHNORR_STR: &str = "Sequential Blind Schnorr";
static ABE_STR: &str = "Parallel Abe";
static FONT: LabelOption<&str> = Font("Fira Sans", 10f64);

// We do this weird structure bc that's how criterion formats its JSON outputs
#[derive(Deserialize, Serialize)]
struct Mean {
    point_estimate: f64,
}
#[derive(Deserialize, Serialize)]
struct Estimate {
    mean: Mean,
}

/// Returns the amount of time (in us) the server spends sending or receiving data in the given
/// scheme with the given number of sessions and bandwidth in Mbps
fn comm_time(scheme: &str, num_sessions: usize, bandwidth: usize) -> f64 {
    // Blind Schnorr sends 3 values. Abe sends 10
    let values_sent_per_session = if scheme == SCHNORR_STR {
        3
    } else if scheme == ABE_STR {
        10
    } else {
        panic!("invalid scheme: {}", scheme);
    };

    // Every value (group elem or scalar) is 32 bytes in Ristretto255
    let total_num_bytes = values_sent_per_session * num_sessions * 32;
    // 1 Mbps = 1 bit per us = 1/8 bytes per us
    let bytes_per_microsecond = (bandwidth as f64) / 8f64;
    let time = (total_num_bytes as f64) / bytes_per_microsecond;

    time
}

/// Returns the mean server runtime (in us) for the specified scheme with the given number of
/// sessions and bandwidth measured in Mbps.
/// This is time to do step 1 + time to do step 2 + time to send/receive all data over the network
fn get_mean_server_runtime(
    scheme: &str,
    num_sessions: usize,
    bandwidth: usize,
) -> Result<f64, Box<dyn Error>> {
    let mut mean_runtime = 0f64;

    // Steps 1 and 3 of the protocol are done on the server side
    for step in &["step 1", "step 3"] {
        let filename =
            format!("./target/criterion/{scheme}/{step}[s = {num_sessions}]/new/estimates.json");
        println!("filename == {filename}");
        let file = File::open(filename)?;
        let estimate: Estimate = serde_json::from_reader(BufReader::new(file))?;

        mean_runtime += estimate.mean.point_estimate;
    }

    mean_runtime += comm_time(scheme, num_sessions, bandwidth);

    Ok(mean_runtime)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fg = Figure::new();
    fg.set_enhanced_text(true);
    let ticks: Vec<Tick<usize, &str>> = SESSION_SIZES
        .iter()
        .map(|n| Tick::Major(*n, Auto))
        .collect();
    let plot = fg
        .axes2d()
        .set_x_log(Some(2f64))
        .set_x_label("Number of sessions", &[FONT])
        .set_y_label("Server runtime (ms)", &[FONT])
        .set_y_ticks(Some((Auto, 0)), &[], &[FONT])
        .set_x_ticks_custom::<_, &str, _, _>(&ticks, &[], &[FONT])
        .set_x_range(Fix(0.7f64), Fix(80f64))
        .set_y_range(Fix(0f64), Fix(5200f64));

    for (&bandwidth, &line_style) in NETWORK_SPEEDS.iter().zip(LINE_STYLES) {
        // Collect (num_sessions, runtime of Abe with num_sessions in ms)
        let abe_runtimes = SESSION_SIZES.iter().map(|num_sessions| {
            get_mean_server_runtime(ABE_STR, *num_sessions, bandwidth).unwrap() / 1000f64
        });
        // Collect (num_sessions, runtime of Abe with num_sessions in ms)
        let schnorr_runtimes = SESSION_SIZES.iter().map(|num_sessions| {
            get_mean_server_runtime(SCHNORR_STR, *num_sessions, bandwidth).unwrap() / 1000f64
        });

        let abe_caption = format!("{ABE_STR} {bandwidth}Mbps");
        let schnorr_caption = format!("{SCHNORR_STR} {bandwidth}Mbps");

        plot.lines_points(
            SESSION_SIZES,
            abe_runtimes,
            &[
                Caption(&abe_caption),
                Color("red"),
                PointSymbol('O'),
                line_style,
            ],
        )
        .lines_points(
            SESSION_SIZES,
            schnorr_runtimes,
            &[
                Caption(&schnorr_caption),
                Color("blue"),
                PointSymbol('S'),
                line_style,
            ],
        );
    }

    fg.show().unwrap();
    //fg.save_to_svg("plots/server_runtime.svg", 1080, 720)
    //.unwrap();

    // And we can draw something in the drawing area
    Ok(())
}
