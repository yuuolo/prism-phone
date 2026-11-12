use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

/// prism-core — rule-based proxy core with a Clash-compatible API.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Config file (Clash/mihomo YAML, sing-box JSON or a share-link list)
    #[arg(short = 'f', long = "config")]
    config: PathBuf,
    /// Home directory (geosite.dat / geoip.dat live here)
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,
    /// Only check the config and exit
    #[arg(short = 't', long)]
    test: bool,
    /// Override external-controller, e.g. 127.0.0.1:9097
    #[arg(long = "ext-ctl")]
    ext_ctl: Option<String>,
    /// Override the API secret
    #[arg(long)]
    secret: Option<String>,
    /// Enable TUN mode (Windows, needs administrator rights and wintun.dll)
    #[arg(long)]
    tun: bool,
    /// With `--convert singbox`: use rule-set files from this directory
    /// (`<tag>.srs`) instead of downloading them at startup
    #[arg(long, value_name = "DIR")]
    rule_set_dir: Option<PathBuf>,
    /// Print the config converted to `clash` or `singbox` format and exit
    #[arg(long, value_name = "FORMAT")]
    convert: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let raw = std::fs::read_to_string(&args.config).with_context(|| format!("read {}", args.config.display()))?;
    let mut profile = prism_core::config::parse_any(&raw)?;
    // Command-line overrides; the hub re-applies them on every reload.
    let source = prism_core::hub::Source {
        path: Some(args.config.clone()),
        ext_ctl: args.ext_ctl.clone(),
        secret: args.secret.clone(),
        tun: args.tun,
    };
    if let Some(c) = &args.ext_ctl {
        profile.general.external_controller = Some(c.clone());
    }
    if let Some(s) = &args.secret {
        profile.general.secret = s.clone();
    }
    if args.tun {
        profile.general.tun.enable = true;
        profile.general.tun.auto_route = true;
    }
    if let Some(fmt) = args.convert.as_deref() {
        let g = &profile.general;
        let o = prism_core::config::clash::Overrides {
            mixed_port: g.mixed_port,
            controller: g.external_controller.clone().unwrap_or_else(|| "127.0.0.1:9090".into()),
            secret: g.secret.clone(),
            mode: g.mode,
            allow_lan: g.allow_lan,
            log_level: g.log_level.clone(),
            tun: g.tun.enable,
            unified_delay: g.unified_delay,
        };
        let out = match fmt {
            "clash" => {
                let mut doc = prism_core::config::clash::emit(&profile);
                prism_core::config::clash::apply_overrides(&mut doc, &o);
                serde_yaml::to_string(&doc)?
            }
            "singbox" => {
                let mut doc = prism_core::config::singbox::emit(&profile, &o);
                if let Some(dir) = &args.rule_set_dir {
                    for tag in prism_core::config::singbox::localize_rule_sets(&mut doc, dir) {
                        eprintln!("warning: {tag} not found in {}, its rules were dropped", dir.display());
                    }
                }
                serde_json::to_string_pretty(&doc)?
            }
            other => anyhow::bail!("unknown format {other} (expected clash or singbox)"),
        };
        print!("{out}");
        return Ok(());
    }
    let level = match profile.general.log_level.as_str() {
        "debug" => "debug",
        "warning" | "warn" => "warn",
        "error" => "error",
        "silent" => "off",
        _ => "info",
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| level.into()))
        .with_ansi(false)
        .with_target(false)
        // With the GUI gone the log pipes are broken: reporting that to stderr
        // would panic in the connection being logged.
        .log_internal_errors(false)
        .init();

    let home = args
        .dir
        .clone()
        .or_else(|| args.config.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    tracing::info!("prism-core {} home={}", env!("CARGO_PKG_VERSION"), home.display());

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        if args.test {
            let core = prism_core::build(profile, &home, &prism_core::BuildEnv::standalone()).await?;
            for w in &core.warnings {
                println!("warning: {w}");
            }
            println!(
                "configuration ok: {} outbounds, {} rules",
                core.tunnel.reg.order.len(),
                core.tunnel.router.rules.len()
            );
            return Ok(());
        }
        let hub = prism_core::hub::Hub::new(source, home, profile).await?;
        prism_core::run(hub).await
    })
}
