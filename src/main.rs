// AleksCypher (c) 2026 AlekssusDev
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;

use crypto::{encrypt_file, decrypt_file, calibrate_rayo_steps};
use eframe::egui;
use egui::Color32;
use rfd::FileDialog;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};
use zeroize::{Zeroize, Zeroizing};

struct TaskResult {
    message: String,
    preview: String,
}

#[derive(Clone, PartialEq)]
enum Operation {
    Encrypt,
    Decrypt,
}

struct AppState {
    operation: Operation,
    file_path: Option<PathBuf>,
    password: String,
    status: String,
    status_color: Color32,
    preview: String,
    pending_result: Arc<Mutex<Option<Result<TaskResult, String>>>>,
    progress: f32,
    padding_level: u8,
    anti_replay: bool,
    rayo_steps: u64,
    calibration_done: bool,
    drag_hover: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            operation: Operation::Encrypt,
            file_path: None,
            password: String::new(),
            status: "Calibrating Rayo machine...".to_owned(),
            status_color: Color32::from_rgb(255, 165, 0),
            preview: String::new(),
            pending_result: Arc::new(Mutex::new(None)),
            progress: 0.0,
            padding_level: 3,
            anti_replay: true,
            rayo_steps: 10_000_000,
            calibration_done: false,
            drag_hover: false,
        }
    }
}

impl AppState {
    fn start_calibration(&mut self) {
        if self.calibration_done { return; }
        let pending = self.pending_result.clone();
        thread::spawn(move || {
            let steps = calibrate_rayo_steps();
            *pending.lock().unwrap() = Some(Ok(TaskResult {
                message: format!("Rayo calibrated: {} steps", steps),
                preview: String::new(),
            }));
        });
    }
}

fn render_3d_star(ui: &mut egui::Ui, ctx: &egui::Context) {
    ctx.request_repaint();
    let time = ctx.input(|i| i.time) as f32 * 1.5;
    let w = 40; let h = 20;
    let mut buf = vec![vec![' '; w]; h];
    let verts = [[0.0,1.0,0.0],[0.0,-1.0,0.0],[1.0,0.0,0.0],[-1.0,0.0,0.0],[0.0,0.0,0.5],[0.0,0.0,-0.5]];
    let edges = [(0,2),(0,3),(0,4),(0,5),(1,2),(1,3),(1,4),(1,5)];
    for &(u,v) in &edges {
        let p1 = verts[u]; let p2 = verts[v];
        for s in 0..=10 {
            let t = s as f32/10.0;
            let mut x = p1[0]+(p2[0]-p1[0])*t;
            let mut y = p1[1]+(p2[1]-p1[1])*t;
            let mut z = p1[2]+(p2[2]-p1[2])*t;
            let nx = x*time.cos() - z*time.sin();
            let nz = x*time.sin() + z*time.cos();
            x = nx; z = nz;
            let ny = y*time.cos() - z*time.sin();
            y = ny;
            let sx = ((x*15.0)+(w as f32/2.0)) as i32;
            let sy = ((y*8.0)+(h as f32/2.0)) as i32;
            if sx>=0 && sx<w as i32 && sy>=0 && sy<h as i32 {
                buf[sy as usize][sx as usize] = if z>0.2 {'#'} else {'*'};
            }
        }
    }
    let art: String = buf.iter().map(|r| r.iter().collect::<String>()).collect::<Vec<_>>().join("\n");
    ui.centered_and_justified(|ui| {
        ui.label(egui::RichText::new(art).font(egui::FontId::monospace(12.0)).color(Color32::from_rgb(186,85,211)));
    });
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.calibration_done && self.rayo_steps == 10_000_000 {
            self.start_calibration();
        }
        if self.rayo_steps == 10_000_000 && !self.calibration_done {
            let mut vis = egui::Visuals::dark();
            vis.panel_fill = Color32::from_rgb(13,5,23);
            vis.window_fill = Color32::from_rgb(20,10,35);
            vis.override_text_color = Some(Color32::from_rgb(186,85,211));
            vis.widgets.active.bg_fill = Color32::from_rgb(147,112,219);
            vis.widgets.hovered.bg_fill = Color32::from_rgb(75,0,130);
            ctx.set_visuals(vis);
        }

        if let Some(res) = self.pending_result.lock().unwrap().take() {
            match res {
                Ok(task) => {
                    let is_calib = task.message.contains("Rayo calibrated");
                    if is_calib {
                        self.rayo_steps = task.message.split_whitespace().last()
                            .and_then(|s| s.parse().ok()).unwrap_or(10_000_000);
                        self.calibration_done = true;
                    }
                    self.status = task.message;
                    self.status_color = Color32::GREEN;
                    if !task.preview.is_empty() { self.preview = task.preview; }
                    self.progress = 1.0;
                }
                Err(err) => {
                    self.status = err;
                    self.status_color = Color32::RED;
                    self.preview.clear();
                    self.progress = 0.0;
                }
            }
        }

        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                if let Some(path) = i.raw.dropped_files[0].path.clone() {
                    if path.is_file() {
                        self.file_path = Some(path);
                    }
                }
            }
        });

        if self.progress > 0.0 && self.progress < 1.0 {
            self.progress += 0.01 * (ctx.input(|i| i.stable_dt.min(0.05)) as f32 * 60.0);
            if self.progress > 0.95 { self.progress = 0.95; }
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.operation, Operation::Encrypt, "Зашифровать");
                ui.selectable_value(&mut self.operation, Operation::Decrypt, "Расшифровать");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading(match self.operation {
                Operation::Encrypt => "Шифрование файла",
                Operation::Decrypt => "Расшифровка файла",
            });
            ui.add_space(8.0);

            let drop_zone = egui::Frame::none()
                .fill(if self.drag_hover { Color32::from_rgb(100, 50, 150) } else { Color32::from_rgb(25, 15, 35) })
                .stroke(egui::Stroke::new(2.0, Color32::from_rgb(186, 85, 211)))
                .rounding(10.0)
                .inner_margin(20.0);

            drop_zone.show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    if let Some(ref path) = self.file_path {
                        ui.label(format!("📄 {}", path.file_name().unwrap_or_default().to_string_lossy()));
                    } else {
                        ui.label("📂 Перетащите файл сюда или нажмите кнопку");
                    }
                    ui.add_space(5.0);
                    if ui.button("📁 Обзор").clicked() {
                        let dialog = FileDialog::new();
                        let picked = match self.operation {
                            Operation::Encrypt => dialog.pick_file(),
                            Operation::Decrypt => dialog.add_filter("GoogolCypher", &["acyph"]).pick_file(),
                        };
                        if let Some(path) = picked {
                            self.file_path = Some(path);
                        }
                    }
                });
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("🔑 Пароль:");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
            });

            if self.operation == Operation::Encrypt {
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.label("📦 Сокрытие размера:");
                    egui::ComboBox::from_id_source("padding")
                        .selected_text(match self.padding_level {
                            0 => "Отключено",
                            1 => "Экономичное",
                            2 => "Стандартное",
                            3 => "Параноидальное",
                            _ => "Отключено",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.padding_level, 0, "Отключено");
                            ui.selectable_value(&mut self.padding_level, 1, "Экономичное (16K-2M)");
                            ui.selectable_value(&mut self.padding_level, 2, "Стандартное (64K-8M)");
                            ui.selectable_value(&mut self.padding_level, 3, "Параноидальное (1M-128M)");
                        });
                });
                ui.add_space(5.0);
                ui.checkbox(&mut self.anti_replay, "🛡️ Anti-replay защита");
            }
            ui.add_space(8.0);

            let btn_enabled = self.file_path.is_some() && !self.password.is_empty() && self.calibration_done;
            let clicked = ui.add_enabled(btn_enabled,
                egui::Button::new(match self.operation {
                    Operation::Encrypt => "🔒 Зашифровать",
                    Operation::Decrypt => "🔓 Расшифровать",
                })
            ).clicked();

            if clicked {
                let file = self.file_path.clone().unwrap();
                let password_bytes = Zeroizing::new(self.password.as_bytes().to_vec());
                self.password.clear();
                self.password.zeroize();

                let pending = self.pending_result.clone();
                let operation = self.operation.clone();
                let anti_replay = self.anti_replay;
                let padding_level = self.padding_level;
                let rayo_steps = self.rayo_steps;
                self.status = "⚡ Deriving key with Rayo machine...".to_owned();
                self.status_color = Color32::from_rgb(255, 165, 0);
                self.progress = 0.01;

                thread::spawn(move || {
                    let result = match operation {
                        Operation::Encrypt => {
                            let out = file.with_extension("acyph");
                            match encrypt_file(&file, &out, &password_bytes, anti_replay, padding_level, rayo_steps) {
                                Ok(()) => Ok(TaskResult {
                                    message: format!("✔ Зашифровано: {}", out.display()),
                                    preview: String::new(),
                                }),
                                Err(e) => Err(format!("❌ Ошибка: {}", e)),
                            }
                        }
                        Operation::Decrypt => {
                            let mut out = file.clone();
                            if out.extension().map(|e| e == "acyph").unwrap_or(false) {
                                out.set_extension("");
                            } else { out.set_extension("decrypted"); }
                            match decrypt_file(&file, &out, &password_bytes) {
                                Ok(()) => {
                                    let prev = std::fs::read_to_string(&out)
                                        .unwrap_or_else(|_| String::new())
                                        .chars().take(200).collect();
                                    Ok(TaskResult {
                                        message: format!("✔ Расшифровано: {}", out.display()),
                                        preview: prev,
                                    })
                                }
                                Err(e) => Err(format!("❌ Ошибка: {}", e)),
                            }
                        }
                    };
                    *pending.lock().unwrap() = Some(result);
                });
            }

            if self.progress > 0.0 && self.progress < 1.0 {
                ui.add_space(6.0);
                ui.add(egui::ProgressBar::new(self.progress).text("⏳ Rayo KDF..."));
            }

            ui.add_space(8.0);
            ui.colored_label(self.status_color, &self.status);

            if !self.preview.is_empty() {
                ui.separator();
                ui.label("👁️ Предпросмотр:");
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut self.preview)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(5));
                });
            }
        });

        egui::TopBottomPanel::bottom("star").min_height(140.0).show(ctx, |ui| {
            render_3d_star(ui, ctx);
        });

        egui::TopBottomPanel::bottom("copyright").min_height(20.0).show(ctx, |ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new("© 2026 AlekssusDev – Licensed under GNU GPL v3")
                        .font(egui::FontId::monospace(10.0))
                        .color(Color32::from_rgb(186, 85, 211))
                );
            });
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 680.0])
            .with_resizable(false),
        ..Default::default()
    };
    eframe::run_native(
        "AleksCypher",
        options,
        Box::new(|_cc| Box::new(AppState::default())),
    )
}