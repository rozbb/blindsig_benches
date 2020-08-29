use std::{error::Error, fs::File, io::BufReader};

use gnuplot::{
    AutoOption::{Auto, Fix},
    AxesCommon, Coordinate, DashType, Figure,
    PlotOption::{self, Caption, Color, LineStyle, PointSymbol},
    Tick, TickOption,
};
use serde::{Deserialize, Serialize};

const INTERARRIVAL_TIMES: &[usize] = &[1, 10, 50, 90, 130];
const THREADPOOL_SIZES: &[usize] = &[1, 4, 16];

static SCHNORR_STR: &str = "Sequential Blind Schnorr";
static ABE_STR: &str = "Parallel Abe";

// We do this weird structure bc that's how criterion formats its JSON outputs
#[derive(Deserialize, Serialize)]
struct Mean {
    point_estimate: f64,
}
#[derive(Deserialize, Serialize)]
struct Estimate {
    mean: Mean,
}

/// Returns the mean server runtime (in ns) for the benchmark on the given scheme with
/// threadpool_size many cores and expected interarrival time of eiat
fn get_mean_server_runtime(
    scheme: &str,
    threadpool_size: usize,
    eiat: usize,
) -> Result<f64, Box<dyn Error>> {
    // Steps 1 and 3 of the protocol are done on the server side
    let filename = format!(
        "./ec2_data/webserver_bench/{}/{}-core server handling 100 clients at \
         {}ms EIAT/new/estimates.json",
        scheme, threadpool_size, eiat
    );
    println!("filename == {}", filename);
    let file = File::open(filename)?;
    let estimate: Estimate = serde_json::from_reader(BufReader::new(file))?;

    Ok(estimate.mean.point_estimate)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fg = Figure::new();
    fg.set_enhanced_text(true);

    // Workload factor is 1 / expected IAT
    let workload_factors: Vec<f64> = INTERARRIVAL_TIMES
        .iter()
        .map(|&iat| (iat as f64).recip())
        .collect();

    // x-axis tickmarks are the workload factors
    let ticks: Vec<Tick<_, &str>> = workload_factors
        .iter()
        .map(|&n| Tick::Major(n, Auto))
        .collect();

    let mut plot = fg
        .axes2d()
        .set_legend(Coordinate::Axis(0.90f64), Coordinate::Axis(14f64), &[], &[])
        .set_x_log(Some(2f64))
        .set_x_label("Workload factor", &[])
        .set_y_label("Runtime (s)", &[])
        .set_y_ticks(Some((Auto, 0)), &[], &[])
        .set_x_ticks_custom::<_, &str, _, _>(&ticks, &[TickOption::Format("%.3f")], &[])
        .set_x_range(Fix(0.0069f64), Fix(1.13f64))
        .set_y_range(Fix(0f64), Fix(15f64));

    // Collect and plot Abe results
    for (&threadpool_size, &point_type) in THREADPOOL_SIZES.iter().zip(
        [
            PlotOption::<&str>::PointSymbol('O'),
            PointSymbol('R'),
            PointSymbol('T'),
        ]
        .iter(),
    ) {
        // Collect (num_sessions, runtime of Abe with num_sessions in sec)
        let abe_runtimes: Vec<f64> = INTERARRIVAL_TIMES
            .iter()
            .map(|&eiat| {
                get_mean_server_runtime(ABE_STR, threadpool_size, eiat).unwrap() / 1_000_000_000f64
            })
            .collect();

        // Plot Abe result as a red line with the given point type
        let line_name = format!("{}-core {}", threadpool_size, ABE_STR);
        plot = plot.lines_points(
            &workload_factors,
            abe_runtimes,
            &[
                Caption(&line_name),
                Color("red"),
                point_type,
                LineStyle(DashType::Solid),
            ],
        );
    }

    // Collect Schnorr data
    let schnorr_runtimes: Vec<f64> = INTERARRIVAL_TIMES
        .iter()
        .map(|&eiat| get_mean_server_runtime(SCHNORR_STR, 1, eiat).unwrap() / 1_000_000_000f64)
        .collect();

    // Plot Schnorr data. This is a blue solid line with square points.
    let line_name = format!("1-core {}", SCHNORR_STR);
    plot.lines_points(
        &workload_factors,
        schnorr_runtimes,
        &[
            Caption(&line_name),
            Color("blue"),
            PointSymbol('S'),
            LineStyle(DashType::Solid),
        ],
    );

    //fg.show().unwrap();
    fg.save_to_svg("plots/server_runtime.svg", 560, 350)
        .unwrap();

    // And we can draw something in the drawing area
    Ok(())
}
