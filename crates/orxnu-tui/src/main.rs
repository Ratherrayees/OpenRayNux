//! The terminal event loop and rendering for the `orxnu-tui` vertical slice.

use std::io::{self, Stdout};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use orxnu_tui::app::ReviewGeometry;
use orxnu_tui::{App, Input};
use orxnuctl::approval::{safe_recipient, safe_text};
use orxnuctl::task::{disclosure_prose_complete, safe_disclosure_prose};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Widget, Wrap},
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
        let size = terminal.size()?;
        let screen = Rect::new(0, 0, size.width, size.height);
        if let Some(review) = app.review.as_ref() {
            debug_assert_eq!(
                review_fits(screen, review),
                review_geometry(screen, review).fits()
            );
            app.set_review_geometry(review_geometry(screen, review));
        }
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
            Input::Proposal | Input::TaskId | Input::TaskContent | Input::Worker => {
                match key.code {
                    KeyCode::Esc => app.cancel_input(),
                    KeyCode::Enter => {
                        app.accept_input();
                    }
                    KeyCode::Backspace => {
                        app.buffer.pop();
                    }
                    KeyCode::Char(c) => app.buffer.push(c),
                    _ => {}
                }
            }
            Input::None => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    app.should_quit = true;
                }
                KeyCode::Char('r') => app.refresh(),
                KeyCode::Char('j') | KeyCode::Down => app.move_selection(1),
                KeyCode::Char('k') | KeyCode::Up => app.move_selection(-1),
                KeyCode::Char('n') => app.begin_task_id_input(),
                KeyCode::Char('i') => app.begin_proposal_input(),
                KeyCode::Char('w') => app.begin_worker_input(),
                KeyCode::Char('l') => app.claim_selected(),
                KeyCode::Char('p') => app.ai_propose_selected(),
                KeyCode::Char('a') => app.request_approval(),
                KeyCode::Char('y') => app.decide_review(true),
                KeyCode::Char('d') => app.decide_review(false),
                KeyCode::Char('e') => app.execute_previewed(),
                KeyCode::Char('x') => app.complete_selected(),
                KeyCode::Char('c') => app.cancel_selected(),
                _ => {}
            },
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// One layout definition shared by rendering and the confirmation gate. If these ever
/// diverge, a key could be accepted for a review the operator cannot see in full.
fn layout_chunks(area: Rect, review_open: bool) -> Vec<Rect> {
    let mut constraints = vec![
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(4),
    ];
    if review_open {
        constraints.insert(2, Constraint::Length(13));
    }
    Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area)
        .to_vec()
}

fn draw(frame: &mut Frame<'_>, app: &App) {
    let chunks = layout_chunks(frame.area(), app.review.is_some());

    render_status(frame, chunks[0], app);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[1]);
    render_tasks(frame, body[0], app);
    render_detail(frame, body[1], app);
    if let Some(review) = &app.review {
        render_review(frame, chunks[2], review);
    }
    let footer = if app.review.is_some() { 3 } else { 2 };
    render_footer(frame, chunks[footer], app);
}

fn render_status(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let line = match &app.status {
        Some(status) => {
            let state = field(status, "status");
            let protocol = field(status, "protocol");
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
        lines.push(Line::from("No tasks. Press n to create one, r to refresh."));
    }

    if let Some(claim) = &app.claim {
        lines.push(Line::from(format!(
            "  claim: task={} worker={} generation={} (from task/claim)",
            safe_text(&claim.task),
            safe_text(&claim.worker),
            claim.generation
        )));
    }

    if let Some(preview) = &app.preview {
        lines.push(Line::from(" "));
        lines.push(Line::from(format!(
            "Proposal {} preview (read-only)",
            app.preview_id
                .as_deref()
                .map(safe_text)
                .unwrap_or_else(|| "?".to_owned())
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
        let uncertainty = verdict.get("uncertainty");
        let task_state = uncertainty
            .and_then(|u| u.get("task_state"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let awaiting = uncertainty
            .and_then(|u| u.get("awaiting"))
            .and_then(Value::as_str)
            .unwrap_or("(not reported)");
        if task_state == "needs-verification" || awaiting == "human-adjudication" {
            lines.push(Line::from(Span::styled(
                format!(
                    "NeedsVerification — {}; the daemon has NOT established the effect. \
                     Treat this as unresolved, not success.",
                    safe_text(awaiting)
                ),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" inspection ")),
        area,
    );
}

fn review_lines(review: &orxnuctl::approval::Review) -> Vec<Line<'static>> {
    let p = review.preview().get("preview");
    let text = |key: &str| {
        p.and_then(|p| p.get(key))
            .and_then(Value::as_str)
            .map(safe_text)
            .unwrap_or_else(|| "(not reported)".to_owned())
    };
    // All structured ceilings live under `preview.disclosure`; reading them from the
    // preview root would silently show "(not reported)" for a real daemon response.
    let dnum = |key: &str| {
        p.and_then(|p| p.get("disclosure"))
            .and_then(|d| d.get(key))
            .and_then(Value::as_u64)
            .map(|n| n.to_string())
            .unwrap_or_else(|| "(not reported)".to_owned())
    };
    let disclosure = |key: &str| {
        p.and_then(|p| p.get("disclosure"))
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .map(safe_disclosure_prose)
            .unwrap_or_default()
    };
    let recipient = p
        .and_then(|p| p.get("recipient"))
        .and_then(Value::as_str)
        .and_then(safe_recipient)
        .unwrap_or_else(|| "(not identified)".to_owned());
    let mut lines = vec![
        Line::from(Span::styled(
            format!(
                "REVIEW REQUIRED — proposal {}",
                safe_text(review.proposal_id())
            ),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  capability: {}", text("capability"))),
        Line::from(format!("  path:       {}", text("path"))),
        Line::from(format!("  operation:  {}", text("operation"))),
        Line::from(format!("  recipient:  {recipient}")),
    ];
    if let Some(reason) = p
        .and_then(|p| p.get("blocked_reason"))
        .and_then(Value::as_str)
    {
        lines.push(Line::from(format!("  blocked:    {}", safe_text(reason))));
    }
    lines.push(Line::from(
        "  Approving MAY disclose this file's contents to the model provider that asked for it.",
    ));
    lines.push(Line::from(format!(
        "  limits: read<={} disclose<={} observations<={} effective={}",
        dnum("read_ceiling_bytes"),
        dnum("observation_ceiling_bytes"),
        dnum("max_entries"),
        dnum("effective_bytes")
    )));
    for detail in [disclosure("limits"), disclosure("timing")] {
        if !detail.is_empty() {
            lines.push(Line::from(format!("    {detail}")));
        }
    }
    if !disclosure_prose_complete(review.preview()) {
        lines.push(Line::from(Span::styled(
            "  INCOMPLETE DISCLOSURE: the full review cannot be displayed; decline with d",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::from(Span::styled(
        "  y confirm and submit the approval   |   d decline (sends nothing)",
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines
}

/// The exact paragraph used to display the review, shared with the geometry probe.
///
/// Both the screen and the measurement go through Ratatui's own `WordWrapper`, so the
/// row count cannot disagree with what a user actually sees. `Paragraph::line_count`
/// would be ideal but is private in this ratatui build without an unstable feature,
/// which would require a manifest change; this probe renders into an offscreen buffer
/// instead and counts the rows the renderer actually wrote.
fn review_paragraph(review: &orxnuctl::approval::Review) -> Paragraph<'static> {
    Paragraph::new(review_lines(review)).wrap(Wrap { trim: false })
}

fn review_required_height(review: &orxnuctl::approval::Review, pane_width: u16) -> u16 {
    let inner_width = pane_width.saturating_sub(2).max(1);
    let probe_area = Rect::new(0, 0, inner_width, 200);
    let mut probe = Buffer::empty(probe_area);
    review_paragraph(review).render(probe_area, &mut probe);
    let used_rows = (0..probe_area.height)
        .filter(|&y| (0..probe_area.width).any(|x| probe[(x, y)].symbol() != " "))
        .count();
    (used_rows as u16).saturating_add(2)
}

/// The single geometry result used by both the event loop and tests.
fn review_geometry(area: Rect, review: &orxnuctl::approval::Review) -> ReviewGeometry {
    // A prose segment that the display bound would truncate makes the review
    // incomplete regardless of how well it fits geometrically. Fail closed here.
    if !disclosure_prose_complete(review.preview()) {
        return ReviewGeometry::from_measurement(0, 0, 1);
    }
    let pane = layout_chunks(area, true)[2];
    ReviewGeometry::from_measurement(
        pane.width,
        pane.height,
        review_required_height(review, pane.width),
    )
}

/// Fail-closed geometry check shared by display and key handling.
fn review_fits(area: Rect, review: &orxnuctl::approval::Review) -> bool {
    review_geometry(area, review).fits()
}

fn render_review(frame: &mut Frame<'_>, area: Rect, review: &orxnuctl::approval::Review) {
    frame.render_widget(
        review_paragraph(review).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" disclosure review "),
        ),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut text = match &app.notice {
        Some(n) if n.is_error => format!(" ERROR: {}", safe_text(&n.text)),
        Some(n) => format!(" {}", safe_text(&n.text)),
        None => String::from(" Ready"),
    };
    if app.input != Input::None {
        let kind = match app.input {
            Input::Proposal => "proposal id",
            Input::TaskId => "new task id",
            Input::TaskContent => "new task content",
            Input::Worker => "worker",
            Input::None => "",
        };
        text.push_str(&format!("\n > {}{}", safe_text(&app.buffer), kind));
    } else if app.review.is_some() {
        text.push_str("\n y confirm | d decline (no approval sent)");
    } else {
        text.push_str(&format!(
            "\n q quit | r refresh | j/k select | n new task | i proposal id | w worker ({}) \
             | l claim | p ai-propose | a approve | e execute | x complete | c cancel",
            safe_text(&app.worker)
        ));
    }
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(" actions ")),
        area,
    );
}

/// Named fields only, sanitized for display.
///
/// A missing or mistyped field renders as `?`, never as a guessed value. Every
/// daemon-supplied string goes through the same bounded sanitizer as the review pane,
/// so a model-controlled target or error string cannot inject terminal control
/// characters or invisible text into a non-review pane. Booleans are rendered from the
/// parsed `Value::Bool`, never from raw JSON text. Static application-owned labels are
/// Numbers are rendered from strict `Value::Number` values, so a valid zero is shown
/// as `0` while a missing or mistyped field remains `?`. Static application-owned
/// labels are not passed through this helper.
fn field(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(s)) => safe_text(s),
        Some(Value::Bool(b)) => (if *b { "true" } else { "false" }).to_owned(),
        Some(Value::Number(n)) if n.is_u64() || n.is_i64() || n.is_f64() => n.to_string(),
        // Null, arrays, objects and unexpected types stay visibly unknown. Rendering
        // their JSON would let a malformed value look like a plausible status.
        _ => "?".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnuctl::approval::{ApprovalStart, PreviewRequests, begin_approval};
    use orxnuctl::client::ClientError;
    use ratatui::backend::TestBackend;
    use serde_json::json;
    use std::sync::Mutex;

    struct Fake {
        replies: Mutex<Vec<Result<Value, ClientError>>>,
    }

    impl PreviewRequests for Fake {
        fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
            let _ = (method, params);
            let mut replies = self.replies.lock().expect("lock");
            if replies.is_empty() {
                return Err(ClientError::Malformed("no reply configured".to_owned()));
            }
            replies.remove(0)
        }
    }

    fn preview(recipient: &str, path: &str, challenge: Option<&str>) -> Value {
        let mut p = json!({
            "preview": {
                "proposal_id": "p-1",
                "proposal_kind": "model-initiated-file-read",
                "requires_confirmation": true,
                "operation": "file-read",
                "approval_allowed": true,
                "capability": "filesystem/read-text",
                "path": path,
                "recipient": recipient,
                "disclosure": {
                    "read_ceiling_bytes": 65536,
                    "observation_ceiling_bytes": 32768,
                    "max_entries": 8,
                    "effective_bytes": 32768,
                    "read_only": true,
                    "disclosure_possible": true,
                    "limits": "an oversized observation is skipped whole",
                    "timing": "only the immediately following step is eligible",
                },
            }
        });
        if let Some(c) = challenge {
            p["preview"]["challenge"] = json!(c);
        }
        p
    }

    fn review_of(recipient: &str, path: &str, challenge: &str) -> orxnuctl::approval::Review {
        let fake = Fake {
            replies: Mutex::new(vec![
                Ok(preview(recipient, path, None)),
                Ok(preview(recipient, path, Some(challenge))),
            ]),
        };
        match begin_approval(&fake, true, "p-1", json!({ "proposal": "p-1" })).expect("review") {
            ApprovalStart::NeedsReview(review) => review,
            ApprovalStart::Submitted { .. } => panic!("a model read must need a review"),
        }
    }

    fn review_from_previews(inspection: Value, fresh: Value) -> orxnuctl::approval::Review {
        let fake = Fake {
            replies: Mutex::new(vec![Ok(inspection), Ok(fresh)]),
        };
        match begin_approval(&fake, true, "p-1", json!({ "proposal": "p-1" })).expect("review") {
            ApprovalStart::NeedsReview(review) => review,
            ApprovalStart::Submitted { .. } => panic!("a model read must need a review"),
        }
    }

    fn render_review_text(review: &orxnuctl::approval::Review) -> String {
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render_review(frame, frame.area(), review))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn render_detail_text(app: &App) -> String {
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render_detail(frame, frame.area(), app))
            .expect("draw");
        buffer_text(terminal.backend().buffer())
    }

    fn render_tasks_text(app: &App) -> String {
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render_tasks(frame, frame.area(), app))
            .expect("draw");
        buffer_text(terminal.backend().buffer())
    }

    fn render_footer_text(app: &App) -> String {
        let backend = TestBackend::new(120, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render_footer(frame, frame.area(), app))
            .expect("draw");
        buffer_text(terminal.backend().buffer())
    }

    fn render_status_text(app: &App) -> String {
        let backend = TestBackend::new(160, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| render_status(frame, frame.area(), app))
            .expect("draw");
        buffer_text(terminal.backend().buffer())
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn the_review_rendering_never_emits_the_challenge() {
        let review = review_of(
            "provider (model: m)",
            "src/main.rs",
            "CHALLENGE-CANARY-9941",
        );
        let text = render_review_text(&review);
        assert!(!text.contains("CHALLENGE-CANARY-9941"), "{text}");
        assert!(text.contains("REVIEW REQUIRED"), "{text}");
    }

    #[test]
    fn an_unsafe_recipient_is_not_rendered_as_a_trusted_label() {
        let recipient = "https://user:CANARY-USER@host/v1?token=CANARY-QUERY#CANARY-FRAG";
        let review = review_of(recipient, "src/main.rs", "challenge");
        let text = render_review_text(&review);
        assert!(text.contains("(not identified)"), "{text}");
        for canary in ["CANARY-USER", "CANARY-QUERY", "CANARY-FRAG"] {
            assert!(
                !text.contains(canary),
                "a canary reached the review: {text}"
            );
        }
    }

    #[test]
    fn control_characters_in_review_fields_cannot_manipulate_the_terminal() {
        let path = "\u{1b}[31mREVIEWED-AND-APPROVED\u{8}\nplain.txt";
        let review = review_of("provider (model: m)", path, "challenge");
        let text = render_review_text(&review);
        assert!(
            !text.contains('\u{1b}'),
            "a raw escape reached the screen: {text}"
        );
        assert!(
            !text.contains('\u{8}'),
            "a raw backspace reached the screen: {text}"
        );
        assert!(
            text.contains("\\u{1b}"),
            "the escape must be shown as a code point: {text}"
        );
        assert!(text.contains("plain.txt"), "{text}");
    }

    #[test]
    fn the_review_renders_the_disclosure_constraints() {
        let review = review_of("provider (model: m)", "src/main.rs", "challenge");
        let text = render_review_text(&review);
        for expected in [
            "65536",
            "32768",
            "8",
            "skipped whole",
            "immediately following step",
            "d decline",
        ] {
            assert!(
                text.contains(expected),
                "the review must show {expected:?}: {text}"
            );
        }
    }

    #[test]
    fn an_uncertain_result_warns_immediately_without_a_refresh() {
        let mut app = App::new();
        app.verdict = Some(json!({
            "verified": false,
            "refuted": false,
            "undetermined": true,
            "uncertainty": {
                "settled": "unknown",
                "task_state": "needs-verification",
                "awaiting": "human-adjudication"
            }
        }));
        let text = render_detail_text(&app);
        assert!(text.contains("NeedsVerification"), "{text}");
        assert!(text.contains("human-adjudication"), "{text}");
        assert!(text.contains("NOT established the effect"), "{text}");
    }

    #[test]
    fn an_ordinary_verdict_does_not_show_the_uncertainty_warning() {
        let mut app = App::new();
        app.verdict = Some(json!({ "verified": true, "refuted": false, "undetermined": false }));
        let text = render_detail_text(&app);
        assert!(!text.contains("NeedsVerification"), "{text}");
    }

    #[test]
    fn an_execute_verdict_flows_into_the_immediate_uncertainty_warning() {
        let reply = json!({
            "verified": false,
            "refuted": false,
            "undetermined": true,
            "result": "the effect could not be established (filesystem/read-text)",
            "uncertainty": {
                "settled": "unknown",
                "task_state": "needs-verification",
                "awaiting": "human-adjudication"
            }
        });
        let mut app = App::new();
        app.verdict = Some(orxnu_tui::app::execution_verdict(&reply));
        let text = render_detail_text(&app);
        assert!(text.contains("NeedsVerification"), "{text}");
        assert!(text.contains("human-adjudication"), "{text}");
        assert!(text.contains("NOT established the effect"), "{text}");
        assert!(text.contains("verified=false"), "{text}");
    }

    #[test]
    fn non_review_panes_escape_model_controlled_bidi_and_control_characters() {
        let mut app = App::new();
        app.tasks = vec![json!({
            "id": "t\u{202e}1\u{1b}[31m",
            "state": "running",
            "last_error": "line one\nline two\u{200b}hidden"
        })];
        let detail = render_detail_text(&app);
        let tasks = render_tasks_text(&app);
        for rendered in [&detail, &tasks] {
            assert!(!rendered.contains('\u{202e}'), "{rendered}");
            assert!(!rendered.contains('\u{1b}'), "{rendered}");
            assert!(rendered.contains("\\u{202e}"), "{rendered}");
            assert!(rendered.contains("\\u{1b}"), "{rendered}");
        }
        assert!(!detail.contains('\u{200b}'), "{detail}");
        assert!(detail.contains("\\u{200b}"), "{detail}");
        assert!(detail.contains("\\u{a}"), "{detail}");
    }

    #[test]
    fn the_model_controlled_inspection_target_is_sanitized_in_the_detail_pane() {
        let mut app = App::new();
        app.preview = Some(json!({
            "preview": {
                "capability": "filesystem/read-text",
                "target": "src/\u{202e}notes.txt",
                "action": "read"
            }
        }));
        let text = render_detail_text(&app);
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(text.contains("notes.txt"), "{text}");
    }

    #[test]
    fn oversized_non_review_fields_are_bounded_and_visible() {
        let mut app = App::new();
        app.tasks = vec![json!({
            "id": "t1",
            "state": "failed",
            "last_error": "E".repeat(500)
        })];
        let text = render_detail_text(&app);
        assert!(text.contains("omitted"), "{text}");
        assert!(text.contains("EE"), "{text}");
        let longest_run = text
            .split(|c: char| c != 'E')
            .map(str::len)
            .max()
            .unwrap_or(0);
        assert!(
            longest_run < 100,
            "the repeated field must be truncated, saw {longest_run} consecutive E characters"
        );
    }

    #[test]
    fn footer_worker_label_is_sanitized() {
        let mut app = App::new();
        app.worker = "w\u{2066}orker".to_owned();
        let text = render_footer_text(&app);
        assert!(!text.contains('\u{2066}'), "{text}");
        assert!(text.contains("\\u{2066}"), "{text}");
    }

    #[test]
    fn status_renders_protocol_number_zero_and_booleans_from_the_daemon_shape() {
        let mut app = App::new();
        app.status = Some(json!({
            "status": "running",
            "protocol": 1,
            "durable_audit": true,
            "capabilities_enabled": 0,
            "transport": "unix"
        }));
        let text = render_status_text(&app);
        assert!(text.contains("daemon=running"), "{text}");
        assert!(text.contains("protocol=1"), "{text}");
        assert!(
            text.contains("capabilities=0"),
            "a valid zero must render as 0: {text}"
        );
        assert!(!text.contains("protocol_version"), "{text}");
    }

    #[test]
    fn status_keeps_missing_null_and_unexpected_types_unknown() {
        let mut app = App::new();
        app.status = Some(json!({
            "status": "running",
            "protocol": null,
            "capabilities_enabled": { "unexpected": true },
            "transport": ["unix", "named-pipe"]
        }));
        let text = render_status_text(&app);
        assert!(text.contains("protocol=?"), "{text}");
        assert!(text.contains("capabilities=?"), "{text}");
        assert!(!text.contains("unexpected"), "{text}");
        assert!(!text.contains("named-pipe"), "{text}");

        let mut missing = App::new();
        missing.status = Some(json!({ "status": "running" }));
        let text = render_status_text(&missing);
        assert!(text.contains("protocol=?"), "{text}");
        assert!(text.contains("capabilities=?"), "{text}");
    }

    #[test]
    fn status_sanitizes_a_hostile_daemon_label() {
        let mut app = App::new();
        app.status = Some(json!({
            "status": "running\u{202e}g UNION SELECT",
            "protocol": 1,
            "capabilities_enabled": 2
        }));
        let text = render_status_text(&app);
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(text.contains("\\u{202e}"), "{text}");
        assert!(text.contains("capabilities=2"), "{text}");
    }

    #[test]
    fn review_confirmation_requires_a_pane_that_shows_every_field() {
        let review = review_of("provider (model: m)", "src/main.rs", "challenge");
        assert!(
            review_fits(Rect::new(0, 0, 160, 40), &review),
            "a normal terminal must allow the review"
        );
        assert!(
            !review_fits(Rect::new(0, 0, 160, 20), &review),
            "a short terminal clips the review and must refuse confirmation"
        );
        assert!(
            !review_fits(Rect::new(0, 0, 30, 40), &review),
            "a narrow terminal wraps the review and must refuse confirmation"
        );
    }

    #[test]
    fn oversized_disclosure_content_can_disable_confirmation_through_wrapping() {
        let long = "R".repeat(200);
        let mut fresh = preview(&long, &long, Some("challenge"));
        fresh["preview"]["capability"] = json!(long.clone());
        fresh["preview"]["blocked_reason"] = json!(long.clone());
        fresh["preview"]["disclosure"]["limits"] = json!(long.clone());
        fresh["preview"]["disclosure"]["timing"] = json!(long.clone());
        let review =
            review_from_previews(preview("provider (model: m)", "src/main.rs", None), fresh);
        let area = Rect::new(0, 0, 120, 40);
        let pane = layout_chunks(area, true)[2];
        assert!(
            !review_fits(area, &review),
            "wrapping that hides review content must fail closed: required={} pane_height={}",
            review_required_height(&review, pane.width),
            pane.height
        );

        let plain = review_of("provider (model: m)", "src/main.rs", "challenge");
        assert!(review_fits(Rect::new(0, 0, 120, 40), &plain));
    }

    const REAL_LIMITS: &str = "A read returns at most 65536 bytes. An observation is \
         released whole: at most 32768 bytes across at most 8 entries per provider request. \
         An observation that does not fit the applicable budget is skipped entirely, not \
         truncated, so a file between those sizes may be read without being disclosed at all.";
    const REAL_TIMING: &str = "Eligibility is limited to the immediately following logical \
         step. A later disclosure is not guaranteed.";

    fn compact(text: &str) -> String {
        text.chars()
            .filter(|c| {
                c.is_alphanumeric() || matches!(c, '.' | ',' | ':' | '=' | '<' | '>' | '-' | '\'')
            })
            .collect()
    }

    fn production_review() -> orxnuctl::approval::Review {
        let mut fresh = preview("provider.example/v1 (model: m)", "a.txt", Some("challenge"));
        fresh["preview"]["disclosure"]["limits"] = json!(REAL_LIMITS);
        fresh["preview"]["disclosure"]["timing"] = json!(REAL_TIMING);
        review_from_previews(
            preview("provider.example/v1 (model: m)", "a.txt", None),
            fresh,
        )
    }

    #[test]
    fn production_disclosure_prose_shows_every_security_fact() {
        let review = production_review();
        let text = compact(&render_review_text(&review));
        for fact in [
            "A read returns at most 65536 bytes.",
            "at most 32768 bytes across at most 8 entries per provider request.",
            "is skipped entirely, not truncated,",
            "Eligibility is limited to the immediately following logical step.",
            "A later disclosure is not guaranteed.",
        ] {
            assert!(
                text.contains(&compact(fact)),
                "the review hides a disclosure fact {fact:?}: {text}"
            );
        }
        let source: String = review_lines(&review)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect();
        assert!(
            source.contains("32768 bytes across at most 8 entries"),
            "the complete prose must be present in review_lines: {source}"
        );
        assert!(
            source.contains("skipped entirely, not truncated"),
            "the complete prose must be present in review_lines: {source}"
        );
    }

    #[test]
    fn hostile_long_prose_is_segmented_and_sanitized_without_losing_facts() {
        let hostile = format!("{REAL_LIMITS}\u{1b}[31m\u{202e}\u{200b}{REAL_TIMING}");
        let mut fresh = preview("provider.example/v1 (model: m)", "a.txt", Some("challenge"));
        fresh["preview"]["disclosure"]["limits"] = json!(hostile);
        fresh["preview"]["disclosure"]["timing"] = json!(REAL_TIMING);
        let review = review_from_previews(
            preview("provider.example/v1 (model: m)", "a.txt", None),
            fresh,
        );
        let rendered = render_review_text(&review);
        for raw in ['\u{1b}', '\u{202e}', '\u{200b}'] {
            assert!(
                !rendered.contains(raw),
                "raw control in review: {rendered:?}"
            );
        }
        assert!(rendered.contains("\\u{1b}"), "{rendered}");
        let text = compact(&rendered);
        assert!(
            text.contains(&compact("skipped entirely, not truncated,")),
            "{text}"
        );
        assert!(
            text.contains(&compact("32768 bytes across at most 8 entries")),
            "{text}"
        );
    }

    #[test]
    fn an_unrenderable_prose_segment_fails_closed_and_is_visible() {
        let mut fresh = preview("provider.example/v1 (model: m)", "a.txt", Some("challenge"));
        fresh["preview"]["disclosure"]["limits"] = json!("Z".repeat(200));
        let review = review_from_previews(
            preview("provider.example/v1 (model: m)", "a.txt", None),
            fresh,
        );
        assert!(
            !review_fits(Rect::new(0, 0, 160, 40), &review),
            "an incomplete disclosure must disable confirmation"
        );
        let text = render_review_text(&review);
        assert!(text.contains("INCOMPLETE DISCLOSURE"), "{text}");
        assert!(text.contains("decline with d"), "{text}");
    }

    #[test]
    fn a_disclosure_too_large_to_show_fails_closed() {
        let mut fresh = preview("provider.example/v1 (model: m)", "a.txt", Some("challenge"));
        fresh["preview"]["disclosure"]["limits"] = json!(REAL_LIMITS.repeat(20));
        let review = review_from_previews(
            preview("provider.example/v1 (model: m)", "a.txt", None),
            fresh,
        );
        assert!(
            !review_fits(Rect::new(0, 0, 160, 40), &review),
            "an incomplete review must never allow confirmation"
        );
        assert!(
            review_required_height(&review, 158) > 13,
            "the renderer-derived height must exceed the fixed pane"
        );
    }

    #[test]
    fn review_shows_nested_ceilings_and_ignores_top_level_decoys() {
        let mut fresh = preview("provider (model: m)", "src/main.rs", Some("challenge"));
        fresh["preview"]["read_ceiling_bytes"] = json!(111);
        fresh["preview"]["observation_ceiling_bytes"] = json!(222);
        fresh["preview"]["max_entries"] = json!(333);
        fresh["preview"]["effective_bytes"] = json!(444);
        let review =
            review_from_previews(preview("provider (model: m)", "src/main.rs", None), fresh);
        let text = render_review_text(&review);
        assert!(text.contains("read<=65536"), "{text}");
        assert!(text.contains("disclose<=32768"), "{text}");
        assert!(text.contains("observations<=8"), "{text}");
        assert!(text.contains("effective=32768"), "{text}");
        for decoy in ["111", "222", "333", "444"] {
            assert!(
                !text.contains(decoy),
                "a top-level decoy was rendered: {text}"
            );
        }
    }

    #[test]
    fn missing_nested_disclosure_fields_are_reported_as_missing() {
        let mut fresh = preview("provider (model: m)", "src/main.rs", Some("challenge"));
        fresh["preview"]["disclosure"] = json!({});
        let review =
            review_from_previews(preview("provider (model: m)", "src/main.rs", None), fresh);
        let text = render_review_text(&review);
        assert!(text.contains("read<=(not reported)"), "{text}");
        assert!(!text.contains("65536"), "{text}");
        assert!(!text.contains("skipped whole"), "{text}");
    }

    #[test]
    fn nested_disclosure_strings_are_sanitized_in_the_review_pane() {
        let mut fresh = preview("provider (model: m)", "src/main.rs", Some("challenge"));
        fresh["preview"]["disclosure"]["limits"] =
            json!("safe\u{1b}[31m\u{202e}limit \u{200b}note");
        let review =
            review_from_previews(preview("provider (model: m)", "src/main.rs", None), fresh);
        let text = render_review_text(&review);
        for raw in ['\u{1b}', '\u{202e}', '\u{200b}'] {
            assert!(!text.contains(raw), "raw control in review: {text:?}");
        }
        assert!(text.contains("\\u{1b}"), "{text}");
        assert!(text.contains("safe"), "{text}");
    }

    #[test]
    fn decoys_do_not_change_measurement_or_rendered_review() {
        let plain = review_of("provider (model: m)", "src/main.rs", "challenge");
        let mut fresh = preview("provider (model: m)", "src/main.rs", Some("challenge"));
        fresh["preview"]["read_ceiling_bytes"] = json!(111);
        fresh["preview"]["observation_ceiling_bytes"] = json!(222);
        let with_decoys =
            review_from_previews(preview("provider (model: m)", "src/main.rs", None), fresh);
        assert_eq!(
            review_required_height(&plain, 118),
            review_required_height(&with_decoys, 118)
        );
        assert_eq!(render_review_text(&plain), render_review_text(&with_decoys));
    }

    #[test]
    fn the_reported_169_cell_path_is_measured_by_the_actual_ratatui_wrapper() {
        let path = format!("{} {} {}", "A".repeat(51), "B".repeat(51), "C".repeat(51));
        assert_eq!("  path:       ".chars().count() + path.chars().count(), 169);
        let review = review_of("provider (model: m)", &path, "challenge");
        let mut saw_clipping_case = false;
        for inner in 98..=102 {
            let area = Rect::new(0, 0, inner, 200);
            let mut buf = Buffer::empty(area);
            review_paragraph(&review).render(area, &mut buf);
            let rendered_rows = (0..area.height)
                .filter(|&y| (0..area.width).any(|x| buf[(x, y)].symbol() != " "))
                .count();
            let measured = review_required_height(&review, inner + 2) as usize;
            assert_eq!(
                measured,
                rendered_rows + 2,
                "inner={inner}: measurement must equal renderer rows plus borders"
            );
            let pane = layout_chunks(Rect::new(0, 0, inner + 2, 40), true)[2];
            assert_eq!(pane.height, 13, "a 40-row terminal gives a 13-row pane");
            assert_eq!(
                review_fits(Rect::new(0, 0, inner + 2, 40), &review),
                rendered_rows + 2 <= pane.height as usize,
                "inner={inner}: gate must follow the renderer"
            );
            if rendered_rows + 2 > pane.height as usize {
                saw_clipping_case = true;
            }
        }
        assert!(
            saw_clipping_case,
            "the reported clipping case must be exercised"
        );
    }

    #[test]
    fn geometry_gate_has_an_exact_minimum_and_fails_one_row_below() {
        let review = review_of("provider (model: m)", "src/main.rs", "challenge");
        let required = review_required_height(&review, 158);
        let mut fitting = None;
        let mut below = None;
        for height in 20..60 {
            let pane = layout_chunks(Rect::new(0, 0, 160, height), true)[2];
            if pane.height == required && fitting.is_none() {
                fitting = Some(height);
            }
            if pane.height == required.saturating_sub(1) && below.is_none() {
                below = Some(height);
            }
        }
        let fitting = fitting.expect("a fitting height exists");
        let below = below.expect("a one-row-smaller height exists");
        assert!(review_fits(Rect::new(0, 0, 160, fitting), &review));
        assert!(!review_fits(Rect::new(0, 0, 160, below), &review));
    }

    #[test]
    fn double_width_and_escaped_tokens_are_included_in_the_measurement() {
        let wide = "東京".repeat(60);
        let wide_review = review_of("provider (model: m)", &wide, "challenge");
        assert!(
            !review_fits(Rect::new(0, 0, 40, 40), &wide_review),
            "double-width wrapping must fail closed on a narrow pane"
        );
        let escaped = format!("{}\u{202e}{}", "E".repeat(80), "F".repeat(80));
        let escaped_review = review_of("provider (model: m)", &escaped, "challenge");
        let inner = 98;
        let area = Rect::new(0, 0, inner, 200);
        let mut buf = Buffer::empty(area);
        review_paragraph(&escaped_review).render(area, &mut buf);
        let rows = (0..area.height)
            .filter(|&y| (0..area.width).any(|x| buf[(x, y)].symbol() != " "))
            .count();
        assert_eq!(
            review_required_height(&escaped_review, inner + 2) as usize,
            rows + 2,
            "escaped control tokens are counted by the renderer, not by scalar guessing"
        );
    }
}
