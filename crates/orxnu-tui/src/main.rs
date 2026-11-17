//! The terminal event loop and rendering for the `orxnu-tui` vertical slice.

use std::io::{self, Stdout};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use orxnu_tui::{App, Input};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use serde_json::Value;

fn main() -> io::Result<()> {
    let mut app = App::new();
    app.refresh();

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    enable_raw_mode()?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;
        if !event::poll(std::time::Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match app.input {
            Input::Proposal | Input::Worker => match key.code {
                KeyCode::Esc => app.cancel_input(),
                KeyCode::Enter => {
                    app.accept_input();
                }
                KeyCode::Backspace => {
                    app.buffer.pop();
                }
                KeyCode::Char(c) => app.buffer.push(c),
                _ => {}
            },
            Input::None => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.should_quit = true;
                }
                KeyCode::Char('r') => app.refresh(),
                KeyCode::Char('j') | KeyCode::Down => app.move_selection(1),
                KeyCode::Char('k') | KeyCode::Up => app.move_selection(-1),
                KeyCode::Char('i') => app.begin_proposal_input(),
                KeyCode::Char('w') => app.begin_worker_input(),
                KeyCode::Char('a') => app.approve_previewed(),
                KeyCode::Char('e') => app.execute_previewed(),
                _ => {}
            },
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(4),
        ])
        .split(area);

    render_status(frame, chunks[0], app);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);
    render_tasks(frame, body[0], app);
    render_detail(frame, body[1], app);
    render_footer(frame, chunks[2], app);
}

fn render_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let line = match &app.status {
        Some(status) => {
            let state = field(status, "status");
            let protocol = field(status, "protocol_version");
            let capabilities = field(status, "capabilities_enabled");
            format!(
                " OpenRayNux  daemon={state}  protocol={protocol}  capabilities={capabilities}  endpoint={}",
                app.endpoint().display()
            )
        }
        None => " OpenRayNux  daemon=unknown (press r to refresh)".to_owned(),
    };
    frame.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" daemon status "),
        ),
        area,
    );
}

fn render_tasks(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let items: Vec<ListItem<'_>> = app
        .tasks
        .iter()
        .enumerate()
        .map(|(i, task)| {
            let id = field(task, "id");
            let state = field(task, "state");
            let style = if state == "needs-verification" {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if i == app.selected { "> " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::styled(id.to_owned(), style),
                Span::raw("  "),
                Span::styled(state.to_owned(), style),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" tasks (j/k) "),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_widget(list, area);
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines: Vec<Line<'_>> = Vec::new();
    if let Some(task) = app.selected_task() {
        lines.push(Line::from("Selected task"));
        for key in [
            "id",
            "state",
            "kind",
            "attempts",
            "max_steps",
            "steps_completed",
            "last_error",
        ] {
            lines.push(Line::from(format!("  {key}: {}", field(task, key))));
        }
        if field(task, "state") == "needs-verification" {
            lines.push(Line::from(Span::styled(
                "  NeedsVerification: the daemon has NOT established the effect. \
                 Treat this as unresolved, not success.",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }
    } else {
        lines.push(Line::from("No tasks. Press r to refresh."));
    }

    if let Some(preview) = &app.preview {
        lines.push(Line::from(" "));
        lines.push(Line::from(format!(
            "Proposal {} preview (read-only)",
            app.preview_id.as_deref().unwrap_or("?")
        )));
        if let Some(p) = preview.get("preview") {
            for key in [
                "capability",
                "target",
                "action",
                "approval_allowed",
                "blocked_reason",
            ] {
                lines.push(Line::from(format!("  {key}: {}", field(p, key))));
            }
        }
    }
    if let Some(verdict) = &app.verdict {
        lines.push(Line::from(" "));
        lines.push(Line::from(format!(
            "Execution verdict (as reported): verified={} refuted={} undetermined={}",
            field(verdict, "verified"),
            field(verdict, "refuted"),
            field(verdict, "undetermined"),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" inspection ")),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut text = match &app.notice {
        Some(n) if n.is_error => format!(" ERROR: {}", n.text),
        Some(n) => format!(" {}", n.text),
        None => String::from(" Ready"),
    };
    if app.input != Input::None {
        text.push_str(&format!(
            "\n > {}{}",
            app.buffer,
            if app.input == Input::Proposal {
                "  (proposal id)"
            } else {
                "  (worker)"
            }
        ));
    } else {
        text.push_str(&format!(
            "\n q quit | r refresh | j/k select | i proposal id | w worker ({}) | a approve | e execute",
            app.worker
        ));
    }
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" actions ")),
        area,
    );
}

/// Named fields only. A missing or mistyped field renders as `?`, never as a guessed
/// value: a surface that invents a status is a surface that lies to its operator.
fn field<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get(key)
                .and_then(Value::as_bool)
                .map(|b| if b { "true" } else { "false" })
        })
        .unwrap_or("?")
}
