//! `aasm cost forecast` — project monthly spending based on current daily rate.

use std::process::ExitCode;

use clap::Args;

use super::client;
use super::models::CostForecastDisplay;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use crate::sanitize::sanitize_terminal;

/// Arguments for `aasm cost forecast`.
#[derive(Args)]
pub struct ForecastArgs {}

/// Run the `aasm cost forecast` command.
pub fn run(_args: ForecastArgs, ctx: &ResolvedContext, output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");

    let resp = match rt.block_on(client::fetch_costs(ctx)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let forecast = build_forecast(&resp);
    render(&forecast, output);
    ExitCode::SUCCESS
}

/// Build a forecast from the cost response.
fn build_forecast(resp: &super::models::CostResponse) -> CostForecastDisplay {
    let date = &resp.date;
    let (day_of_month, days_in_month) = parse_date_parts(date);

    let daily_spend: f64 = resp.daily_spend_usd.parse().unwrap_or(0.0);
    let projected = if day_of_month > 0 {
        daily_spend * days_in_month as f64
    } else {
        0.0
    };

    let utilization_pct = resp.monthly_limit_usd.as_ref().and_then(|limit_str| {
        let limit: f64 = limit_str.parse().ok()?;
        if limit <= 0.0 {
            return None;
        }
        Some(format!("{:.1}%", (projected / limit) * 100.0))
    });

    CostForecastDisplay {
        date: date.clone(),
        day_of_month,
        days_in_month,
        current_daily_spend: resp.daily_spend_usd.clone(),
        projected_monthly_spend: format!("{projected:.2}"),
        monthly_limit_usd: resp.monthly_limit_usd.clone(),
        projected_utilization_pct: utilization_pct,
    }
}

/// Parse YYYY-MM-DD into (day_of_month, days_in_month).
fn parse_date_parts(date_str: &str) -> (u32, u32) {
    let parts: Vec<&str> = date_str.split('-').collect();
    if parts.len() != 3 {
        return (1, 30);
    }
    let year: i32 = parts[0].parse().unwrap_or(2026);
    let month: u32 = parts[1].parse().unwrap_or(1);
    let day: u32 = parts[2].parse().unwrap_or(1);

    let days_in_month = days_in_month(year, month);
    (day, days_in_month)
}

/// Return the number of days in a given month.
fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

fn render(forecast: &CostForecastDisplay, output: OutputFormat) {
    match output {
        OutputFormat::Table => render_table(forecast),
        OutputFormat::Json => render_json(forecast),
        OutputFormat::Yaml => render_yaml(forecast),
    }
}

fn render_json(forecast: &CostForecastDisplay) {
    match serde_json::to_string_pretty(forecast) {
        Ok(json) => println!("{json}"),
        Err(e) => eprintln!("error serializing JSON: {e}"),
    }
}

fn render_yaml(forecast: &CostForecastDisplay) {
    match serde_yaml::to_string(forecast) {
        Ok(yaml) => print!("{yaml}"),
        Err(e) => eprintln!("error serializing YAML: {e}"),
    }
}

fn render_table(forecast: &CostForecastDisplay) {
    println!("COST FORECAST");
    println!("─────────────");
    // Server-supplied money/date strings; strip terminal escapes.
    println!("  Date:              {}", sanitize_terminal(&forecast.date));
    println!(
        "  Day of month:      {}/{}",
        forecast.day_of_month, forecast.days_in_month
    );
    println!(
        "  Current daily:     ${}",
        sanitize_terminal(&forecast.current_daily_spend)
    );
    println!(
        "  Projected monthly: ${}",
        sanitize_terminal(&forecast.projected_monthly_spend)
    );
    if let Some(ref limit) = forecast.monthly_limit_usd {
        println!("  Monthly limit:     ${}", sanitize_terminal(limit));
    }
    if let Some(ref pct) = forecast.projected_utilization_pct {
        println!("  Projected util:    {pct}");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_date_parts_normal() {
        let (day, days) = parse_date_parts("2026-04-15");
        assert_eq!(day, 15);
        assert_eq!(days, 30);
    }

    #[test]
    fn parse_date_parts_feb_leap_year() {
        let (day, days) = parse_date_parts("2024-02-10");
        assert_eq!(day, 10);
        assert_eq!(days, 29);
    }

    #[test]
    fn parse_date_parts_feb_non_leap() {
        let (day, days) = parse_date_parts("2025-02-10");
        assert_eq!(day, 10);
        assert_eq!(days, 28);
    }

    #[test]
    fn parse_date_parts_january() {
        let (day, days) = parse_date_parts("2026-01-31");
        assert_eq!(day, 31);
        assert_eq!(days, 31);
    }

    #[test]
    fn days_in_month_all_months() {
        assert_eq!(days_in_month(2026, 1), 31);
        assert_eq!(days_in_month(2026, 2), 28);
        assert_eq!(days_in_month(2026, 3), 31);
        assert_eq!(days_in_month(2026, 4), 30);
        assert_eq!(days_in_month(2026, 5), 31);
        assert_eq!(days_in_month(2026, 6), 30);
        assert_eq!(days_in_month(2026, 7), 31);
        assert_eq!(days_in_month(2026, 8), 31);
        assert_eq!(days_in_month(2026, 9), 30);
        assert_eq!(days_in_month(2026, 10), 31);
        assert_eq!(days_in_month(2026, 11), 30);
        assert_eq!(days_in_month(2026, 12), 31);
    }

    #[test]
    fn build_forecast_basic() {
        let resp = super::super::models::CostResponse {
            daily_spend_usd: "10.00".to_string(),
            monthly_spend_usd: Some("150.00".to_string()),
            date: "2026-04-15".to_string(),
            daily_limit_usd: Some("50.00".to_string()),
            monthly_limit_usd: Some("500.00".to_string()),
            per_agent: vec![],
        };
        let forecast = build_forecast(&resp);
        assert_eq!(forecast.day_of_month, 15);
        assert_eq!(forecast.days_in_month, 30);
        assert_eq!(forecast.projected_monthly_spend, "300.00");
        assert_eq!(forecast.projected_utilization_pct.as_deref(), Some("60.0%"));
    }

    #[test]
    fn build_forecast_no_limit() {
        let resp = super::super::models::CostResponse {
            daily_spend_usd: "5.00".to_string(),
            monthly_spend_usd: None,
            date: "2026-01-10".to_string(),
            daily_limit_usd: None,
            monthly_limit_usd: None,
            per_agent: vec![],
        };
        let forecast = build_forecast(&resp);
        assert_eq!(forecast.projected_monthly_spend, "155.00");
        assert!(forecast.projected_utilization_pct.is_none());
    }
}
