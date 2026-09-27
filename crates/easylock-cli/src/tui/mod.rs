//! `easylock tui` — a full-screen terminal UI over easylock-core.
//!
//! Layout: tool list on the left, the selected tool on the right (a short
//! explanation, its input fields, and live results), key hints at the bottom.
//! Everything is localised in English, Turkish and Spanish (`F2` cycles).

mod tools;

use crate::i18n::{CliError, Lang, Msg};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use tools::{FieldKind, Tool};

const ACCENT: Color = Color::Rgb(94, 176, 239);
const DIM: Color = Color::Rgb(120, 132, 148);
const GOOD: Color = Color::Rgb(78, 201, 165);
const WARN: Color = Color::Rgb(232, 176, 75);
const BAD: Color = Color::Rgb(239, 106, 106);

#[derive(PartialEq, Eq, Clone, Copy)]
enum Focus {
    Sidebar,
    Field(usize),
}

struct App {
    lang: Lang,
    tools: Vec<Tool>,
    selected: usize,
    focus: Focus,
    help: bool,
    status: (String, Color),
    quit: bool,
}

impl App {
    fn new(lang: Lang) -> Self {
        let mut app = Self {
            lang,
            tools: tools::all(),
            selected: 0,
            focus: Focus::Sidebar,
            help: false,
            status: (String::new(), DIM),
            quit: false,
        };
        app.recompute_live();
        app
    }

    fn tool(&self) -> &Tool {
        &self.tools[self.selected]
    }
    fn tool_mut(&mut self) -> &mut Tool {
        &mut self.tools[self.selected]
    }

    fn set_status(&mut self, msg: impl Into<String>, color: Color) {
        self.status = (msg.into(), color);
    }

    fn recompute_live(&mut self) {
        let lang = self.lang;
        let tool = self.tool_mut();
        if tool.live {
            tool.run(lang);
        }
    }

    fn run_action(&mut self) {
        let lang = self.lang;
        let tool = self.tool_mut();
        tool.run(lang);
        let err = tool.error.clone();
        if let Some(e) = err {
            self.set_status(e, BAD);
        } else {
            self.set_status(lang.pick(["done ✓", "tamam ✓", "listo ✓"]), GOOD);
        }
    }

    fn copy_output(&mut self) {
        let text = self
            .tool()
            .output
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() {
            return;
        }
        let ok = copy_to_clipboard(&text);
        let msg = if ok {
            self.lang.pick([
                "copied to clipboard",
                "panoya kopyalandı",
                "copiado al portapapeles",
            ])
        } else {
            self.lang.pick([
                "clipboard unavailable (sent OSC 52)",
                "pano kullanılamıyor (OSC 52 gönderildi)",
                "portapapeles no disponible (se envió OSC 52)",
            ])
        };
        self.set_status(msg, if ok { GOOD } else { WARN });
    }

    fn on_key(&mut self, key: KeyEvent) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

        // Global keys.
        match key.code {
            KeyCode::Char('c') if ctrl => {
                self.quit = true;
                return;
            }
            KeyCode::F(2) => {
                self.lang = self.lang.next();
                self.recompute_live();
                self.set_status(format!("🌐 {}", self.lang.endonym()), ACCENT);
                return;
            }
            KeyCode::Char('l') if ctrl => {
                self.lang = self.lang.next();
                self.recompute_live();
                self.set_status(format!("🌐 {}", self.lang.endonym()), ACCENT);
                return;
            }
            KeyCode::F(1) => {
                self.help = !self.help;
                return;
            }
            KeyCode::F(5) => {
                self.copy_output();
                return;
            }
            KeyCode::Char('y') if ctrl => {
                self.copy_output();
                return;
            }
            _ => {}
        }
        if self.help {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?' | 'q')
            ) {
                self.help = false;
            }
            return;
        }

        match self.focus {
            Focus::Sidebar => self.on_sidebar_key(key),
            Focus::Field(i) => self.on_field_key(i, key),
        }
    }

    fn on_sidebar_key(&mut self, key: KeyEvent) {
        let n = self.tools.len();
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = (self.selected + 1) % n;
                self.recompute_live();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = (self.selected + n - 1) % n;
                self.recompute_live();
            }
            KeyCode::Char(c @ '1'..='9') => {
                let i = (c as usize) - ('1' as usize);
                if i < n {
                    self.selected = i;
                    self.recompute_live();
                }
            }
            KeyCode::Enter | KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                if self.tool().fields.is_empty() {
                    self.run_action();
                } else {
                    self.focus = Focus::Field(0);
                }
            }
            _ => {}
        }
    }

    fn on_field_key(&mut self, i: usize, key: KeyEvent) {
        let nfields = self.tool().fields.len();
        match key.code {
            KeyCode::Esc => {
                self.focus = Focus::Sidebar;
                return;
            }
            KeyCode::Tab | KeyCode::Down => {
                self.focus = Focus::Field((i + 1) % nfields);
                return;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = if i == 0 {
                    Focus::Sidebar
                } else {
                    Focus::Field(i - 1)
                };
                return;
            }
            KeyCode::Enter => {
                self.run_action();
                return;
            }
            _ => {}
        }

        let lang = self.lang;
        let field = &mut self.tool_mut().fields[i];
        let changed = match &field.kind {
            FieldKind::Text | FieldKind::Secret => match key.code {
                KeyCode::Char(c) => {
                    field.value.push(c);
                    true
                }
                KeyCode::Backspace => field.value.pop().is_some(),
                _ => false,
            },
            FieldKind::Choice(opts) => {
                let len = opts.len();
                let cur = opts.iter().position(|o| *o == field.value).unwrap_or(0);
                match key.code {
                    KeyCode::Right | KeyCode::Char(' ' | 'l') => {
                        field.value = opts[(cur + 1) % len].to_string();
                        true
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        field.value = opts[(cur + len - 1) % len].to_string();
                        true
                    }
                    _ => false,
                }
            }
            FieldKind::Number { min, max } => {
                let (min, max) = (*min, *max);
                let v: i64 = field.value.parse().unwrap_or(min);
                let nv = match key.code {
                    KeyCode::Right | KeyCode::Char('+' | 'l') => (v + 1).min(max),
                    KeyCode::Left | KeyCode::Char('-' | 'h') => (v - 1).max(min),
                    KeyCode::Char(c) if c.is_ascii_digit() => {
                        let s = format!("{}{c}", field.value);
                        s.parse::<i64>().unwrap_or(v).min(max)
                    }
                    KeyCode::Backspace => {
                        let mut s = field.value.clone();
                        s.pop();
                        s.parse().unwrap_or(min)
                    }
                    _ => v,
                };
                let changed = nv != v;
                field.value = nv.to_string();
                changed
            }
            FieldKind::Toggle => match key.code {
                KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
                    field.value = if field.value == "on" {
                        "off".into()
                    } else {
                        "on".into()
                    };
                    true
                }
                _ => false,
            },
        };
        if changed {
            let tool = self.tool_mut();
            if tool.live {
                tool.run(lang);
            }
        }
    }
}

/// Copy via the platform clipboard tool, falling back to an OSC 52 escape.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let candidates: &[(&str, &[&str])] = &[
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ];
    for (cmd, args) in candidates {
        if let Ok(mut child) = Command::new(cmd).args(*args).stdin(Stdio::piped()).spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if child.wait().is_ok_and(|s| s.success()) {
                return true;
            }
        }
    }
    let b64 = easylock_core::encode::base64::encode(
        text.as_bytes(),
        easylock_core::encode::base64::Variant::Standard,
    );
    let _ = write!(std::io::stdout(), "\x1b]52;c;{b64}\x07");
    let _ = std::io::stdout().flush();
    false
}

// --- rendering -------------------------------------------------------------

fn draw(f: &mut Frame<'_>, app: &App) {
    let [top, body, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(f.area());

    draw_topbar(f, top, app);
    let [side, main] = Layout::horizontal([Constraint::Length(30), Constraint::Min(0)]).areas(body);
    draw_sidebar(f, side, app);
    draw_tool(f, main, app);
    draw_bottom(f, bottom, app);

    if app.help {
        draw_help(f, app);
    }
}

fn draw_topbar(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lang = app.lang;
    let left = Line::from(vec![
        Span::styled(
            " 🔒 easylock ",
            Style::new().fg(Color::Black).bg(ACCENT).bold(),
        ),
        Span::raw(" "),
        Span::styled(
            lang.pick([
                "terminal cryptography toolkit",
                "terminal kriptografi araç seti",
                "kit de criptografía en terminal",
            ]),
            Style::new().fg(DIM),
        ),
    ]);
    f.render_widget(Paragraph::new(left), area);
    let langs: Vec<Span<'_>> = Lang::ALL
        .iter()
        .flat_map(|l| {
            let st = if *l == lang {
                Style::new().fg(Color::Black).bg(ACCENT).bold()
            } else {
                Style::new().fg(DIM)
            };
            [
                Span::styled(format!(" {} ", l.code().to_uppercase()), st),
                Span::raw(" "),
            ]
        })
        .collect();
    f.render_widget(
        Paragraph::new(Line::from(langs)).alignment(Alignment::Right),
        area,
    );
}

fn draw_sidebar(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lang = app.lang;
    let focused = app.focus == Focus::Sidebar;
    let items: Vec<ListItem<'_>> = app
        .tools
        .iter()
        .enumerate()
        .map(|(i, t)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", i + 1), Style::new().fg(DIM)),
                Span::raw(format!("{} ", t.icon)),
                Span::raw(lang.pick(t.name)),
            ]))
        })
        .collect();
    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", lang.pick(["Tools", "Araçlar", "Herramientas"])),
            Style::new().bold(),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if focused { ACCENT } else { DIM }));
    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut state = ListState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(list, area, &mut state);
}

#[allow(clippy::too_many_lines)] // linear widget layout; splitting it hurts readability
fn draw_tool(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lang = app.lang;
    let tool = app.tool();
    let outer = Block::default()
        .title(Span::styled(
            format!(" {} {} ", tool.icon, lang.pick(tool.name)),
            Style::new().bold().fg(ACCENT),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(if app.focus == Focus::Sidebar {
            DIM
        } else {
            ACCENT
        }));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let desc_h = 3;
    let fields_h = u16::try_from(tool.fields.len()).unwrap_or(0) * 3;
    let [desc, fields, out] = Layout::vertical([
        Constraint::Length(desc_h),
        Constraint::Length(fields_h),
        Constraint::Min(3),
    ])
    .areas(inner);

    f.render_widget(
        Paragraph::new(lang.pick(tool.about))
            .style(Style::new().fg(DIM))
            .wrap(Wrap { trim: true }),
        desc,
    );

    // fields
    let rows = Layout::vertical(tool.fields.iter().map(|_| Constraint::Length(3))).split(fields);
    for (i, (field, row)) in tool.fields.iter().zip(rows.iter()).enumerate() {
        let focused = app.focus == Focus::Field(i);
        let shown = match field.kind {
            FieldKind::Secret => "•".repeat(field.value.chars().count()),
            FieldKind::Choice(_) | FieldKind::Number { .. } => format!("◀ {} ▶", field.value),
            FieldKind::Toggle => {
                if field.value == "on" {
                    "[x]".into()
                } else {
                    "[ ]".into()
                }
            }
            FieldKind::Text => field.value.clone(),
        };
        let cursor = if focused && matches!(field.kind, FieldKind::Text | FieldKind::Secret) {
            "▏"
        } else {
            ""
        };
        let block = Block::default()
            .title(Span::styled(
                format!(" {} ", lang.pick(field.label)),
                Style::new().fg(if focused { ACCENT } else { DIM }),
            ))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(if focused {
                ACCENT
            } else {
                Color::Rgb(60, 68, 80)
            }));
        f.render_widget(
            Paragraph::new(format!("{shown}{cursor}")).block(block),
            *row,
        );
    }

    // output
    let mut lines: Vec<Line<'_>> = Vec::new();
    if let Some(err) = &tool.error {
        lines.push(Line::from(Span::styled(
            format!("✕ {err}"),
            Style::new().fg(BAD),
        )));
    }
    for (label, value) in &tool.output {
        lines.push(Line::from(Span::styled(
            label.clone(),
            Style::new().fg(DIM),
        )));
        lines.push(Line::from(Span::styled(
            value.clone(),
            Style::new().fg(GOOD),
        )));
        lines.push(Line::default());
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            lang.pick(tool.hint),
            Style::new().fg(DIM).add_modifier(Modifier::ITALIC),
        )));
    }
    let out_block = Block::default()
        .title(Span::styled(
            format!(" {} ", lang.pick(["Result", "Sonuç", "Resultado"])),
            Style::new().bold(),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(Color::Rgb(60, 68, 80)));
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .block(out_block)
            .wrap(Wrap { trim: false }),
        out,
    );
}

fn draw_bottom(f: &mut Frame<'_>, area: Rect, app: &App) {
    let lang = app.lang;
    let [status, keys] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {}", app.status.0),
            Style::new().fg(app.status.1),
        )),
        status,
    );
    let hint = |k: &'static str, v: &'static str| {
        [
            Span::styled(format!(" {k} "), Style::new().fg(Color::Black).bg(DIM)),
            Span::styled(format!(" {v}  "), Style::new().fg(DIM)),
        ]
    };
    let mut spans: Vec<Span<'_>> = Vec::new();
    spans.extend(hint("↑↓", lang.pick(["move", "gezin", "mover"])));
    spans.extend(hint("Tab", lang.pick(["fields", "alanlar", "campos"])));
    spans.extend(hint("←→", lang.pick(["change", "değiştir", "cambiar"])));
    spans.extend(hint("Enter", lang.pick(["run", "çalıştır", "ejecutar"])));
    spans.extend(hint("F5", lang.pick(["copy", "kopyala", "copiar"])));
    spans.extend(hint("F2", lang.pick(["language", "dil", "idioma"])));
    spans.extend(hint("F1", lang.pick(["help", "yardım", "ayuda"])));
    spans.extend(hint(
        "Esc",
        lang.pick(["back/quit", "geri/çık", "atrás/salir"]),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), keys);
}

#[allow(clippy::too_many_lines)] // linear widget layout; splitting it hurts readability
fn draw_help(f: &mut Frame<'_>, app: &App) {
    let lang = app.lang;
    let area = centered(f.area(), 68, 20);
    f.render_widget(Clear, area);
    let rows: [(&str, [&str; 3]); 11] = [
        (
            "↑ ↓ / j k",
            ["choose a tool", "araç seç", "elegir herramienta"],
        ),
        (
            "1 … 9",
            ["jump to tool", "araca atla", "saltar a herramienta"],
        ),
        (
            "Enter / Tab",
            [
                "open the tool's fields",
                "aracın alanlarına gir",
                "entrar en los campos",
            ],
        ),
        (
            "Tab / Shift-Tab",
            [
                "next / previous field",
                "sonraki / önceki alan",
                "campo siguiente / anterior",
            ],
        ),
        (
            "← →  space",
            [
                "change a choice / number",
                "seçimi / sayıyı değiştir",
                "cambiar opción / número",
            ],
        ),
        (
            "Enter (in a field)",
            [
                "run / regenerate",
                "çalıştır / yeniden üret",
                "ejecutar / regenerar",
            ],
        ),
        (
            "F5  Ctrl-Y",
            [
                "copy result to clipboard",
                "sonucu panoya kopyala",
                "copiar resultado",
            ],
        ),
        (
            "F2  Ctrl-L",
            ["EN → TR → ES", "EN → TR → ES", "EN → TR → ES"],
        ),
        (
            "F1  ?",
            [
                "toggle this help",
                "bu yardımı aç/kapat",
                "mostrar/ocultar ayuda",
            ],
        ),
        (
            "Esc",
            [
                "back to the tool list",
                "araç listesine dön",
                "volver a la lista",
            ],
        ),
        ("q  Ctrl-C", ["quit", "çık", "salir"]),
    ];
    let mut lines = vec![
        Line::from(Span::styled(
            lang.pick([
                "Keyboard shortcuts",
                "Klavye kısayolları",
                "Atajos de teclado",
            ]),
            Style::new().bold().fg(ACCENT),
        )),
        Line::default(),
    ];
    for (k, v) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("  {k:<20}"), Style::new().fg(WARN)),
            Span::raw(lang.pick(v)),
        ]));
    }
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        lang.pick([
            "Everything runs locally. From-scratch, unaudited crypto — for learning.",
            "Her şey yerelde çalışır. Sıfırdan, denetlenmemiş kripto — öğrenme amaçlı.",
            "Todo se ejecuta localmente. Criptografía desde cero y sin auditar — para aprender.",
        ]),
        Style::new().fg(DIM).italic(),
    )));
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(ACCENT)),
        ),
        area,
    );
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

// --- entry point ------------------------------------------------------------

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    while !app.quit {
        terminal.draw(|f| draw(f, app))?;
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                app.on_key(key);
            }
        }
    }
    Ok(())
}

/// Launch the TUI. Restores the terminal even on error.
pub fn run(lang: Lang) -> Result<(), CliError> {
    let mut terminal = ratatui::init();
    let mut app = App::new(lang);
    let res = event_loop(&mut terminal, &mut app);
    ratatui::restore();
    res.map_err(|e| CliError::new(Msg::TerminalError(e.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn renders_in_all_languages() {
        for (lang, needle) in [
            (Lang::En, "Tools"),
            (Lang::Tr, "Araçlar"),
            (Lang::Es, "Herramientas"),
        ] {
            let app = App::new(lang);
            assert!(render(&app).contains(needle), "{lang:?}");
        }
    }

    #[test]
    fn typing_into_hash_updates_live() {
        let mut app = App::new(Lang::En);
        app.on_key(KeyEvent::from(KeyCode::Enter)); // into fields
        for c in "abc".chars() {
            app.on_key(KeyEvent::from(KeyCode::Char(c)));
        }
        let out = render(&app);
        assert!(out.contains("ba7816bf8f01cfea414140de5dae2223"), "{out}");
    }

    #[test]
    fn f2_cycles_language_and_help_toggles() {
        let mut app = App::new(Lang::En);
        app.on_key(KeyEvent::from(KeyCode::F(2)));
        assert_eq!(app.lang, Lang::Tr);
        app.on_key(KeyEvent::from(KeyCode::F(1)));
        assert!(render(&app).contains("Klavye kısayolları"));
    }

    #[test]
    fn every_tool_renders_and_runs() {
        let mut app = App::new(Lang::Es);
        for i in 0..app.tools.len() {
            app.selected = i;
            app.run_action();
            let _ = render(&app);
        }
    }
}
