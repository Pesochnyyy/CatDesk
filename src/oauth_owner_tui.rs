//! Local terminal controls for the original CatDesk OAuth authorization flow.
//! Never exposed as HTTP endpoints. No active session in production yet.
use crate::oauth::OAuthSettings;
use crate::oauth_http::{OAuthHttpState, PendingApproval};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{error::Error, io::Stdout, time::Duration};
use zeroize::Zeroize;

type OwnerTerminal = Terminal<CrosstermBackend<Stdout>>;
type OwnerResult<T> = Result<T, Box<dyn Error>>;
const POLL: Duration = Duration::from_millis(80);

fn panel_lines(
    pending: &[PendingApproval],
    selected: usize,
    status: &str,
    active: bool,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from("LOCAL OAuth owner controls"),
        Line::from("Owner keys must never be entered into a browser page."),
        Line::from(""),
    ];
    if !active {
        lines.push(Line::from(
            "INACTIVE: no OAuth session attached to this application.",
        ));
        lines.push(Line::from("Public Funnel remains disabled."));
    } else if pending.is_empty() {
        lines.push(Line::from("No pending authorization requests."));
    } else {
        for (index, item) in pending.iter().enumerate().take(12) {
            let mark = if index == selected { ">" } else { " " };
            lines.push(Line::from(format!(
                "{mark} {} [{}]",
                item.client_id, item.scope
            )));
            lines.push(Line::from(format!("    Resource: {}", item.resource)));
            lines.push(Line::from(format!("    Request: {}", item.request_id)));
        }
    }
    lines.extend([
        Line::from(""),
        Line::from("Up/Down select | A approve | D deny | X revoke ALL | R refresh"),
        Line::from("Esc or Q return"),
        Line::from(format!("Status: {status}")),
    ]);
    lines
}

fn render_panel(
    f: &mut Frame,
    pending: &[PendingApproval],
    selected: usize,
    status: &str,
    active: bool,
) {
    f.render_widget(
        Paragraph::new(panel_lines(pending, selected, status, active))
            .block(
                Block::default()
                    .title(" Original CatDesk / OAuth Owner ")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true }),
        f.area(),
    );
}

async fn confirm(terminal: &mut OwnerTerminal, message: &str) -> OwnerResult<bool> {
    loop {
        terminal.draw(|f| {
            f.render_widget(
                Paragraph::new(format!(
                    "{message}\n\nPress Y to confirm; any other key cancels."
                ))
                .block(
                    Block::default()
                        .title(" Confirm local action ")
                        .borders(Borders::ALL),
                ),
                f.area(),
            );
        })?;
        if event::poll(POLL)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    return Ok(matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')));
                }
            }
        }
    }
}

async fn read_secret_locally(terminal: &mut OwnerTerminal) -> OwnerResult<Option<String>> {
    let mut secret = String::with_capacity(64);
    loop {
        let masked = "•".repeat(secret.len());
        terminal.draw(|f| {
            f.render_widget(
                Paragraph::new(vec![
                    Line::from("Type owner key only in this LOCAL terminal. Input is hidden."),
                    Line::from(masked),
                    Line::from("Enter: verify (64 characters) | Esc: cancel"),
                ])
                .block(
                    Block::default()
                        .title(" OWNER KEY ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                ),
                f.area(),
            );
        })?;
        if !event::poll(POLL)? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Esc => {
                    secret.zeroize();
                    return Ok(None);
                }
                KeyCode::Backspace => {
                    secret.pop();
                }
                KeyCode::Enter if secret.len() == 64 => return Ok(Some(secret)),
                KeyCode::Char(c) if secret.len() < 64 && c.is_ascii_hexdigit() => secret.push(c),
                _ => {}
            },
            Event::Paste(text)
                if text.len() <= 64 - secret.len()
                    && text.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                secret.push_str(&text)
            }
            _ => {}
        }
    }
}
/// Local-only, one-time opt-in. This does not start any network transport.
/// The owner supplies an ephemeral 64-hex secret in the native terminal; it
/// remains only in the process memory and is never persisted or logged.
pub(crate) async fn activate_loopback_session(
    terminal: &mut OwnerTerminal,
    settings: OAuthSettings,
    port: u16,
) -> OwnerResult<Option<OAuthHttpState>> {
    if !confirm(terminal,
        "Enable LOCAL-ONLY OAuth acceptance for this one CatDesk process?\nPublic Funnel stays OFF. No ChatGPT remote access is enabled.\nUse a NEW 64-character hexadecimal owner key.",
    ).await? {
        return Ok(None);
    }
    let Some(mut key) = read_secret_locally(terminal).await? else {
        return Ok(None);
    };
    let result = OAuthHttpState::new_local_acceptance(settings, &key, port);
    key.zeroize();
    match result {
        Ok(session) => Ok(Some(session)),
        Err(error) => Err(format!("Local OAuth setup rejected: {error:?}").into()),
    }
}

pub(crate) async fn run_owner_panel(
    terminal: &mut OwnerTerminal,
    oauth: Option<&OAuthHttpState>,
) -> OwnerResult<()> {
    let mut pending = if let Some(oauth) = oauth {
        oauth.pending_requests_locally().await
    } else {
        vec![]
    };
    let mut selected = 0usize;
    let mut status = if oauth.is_some() {
        "Local owner controls ready".to_string()
    } else {
        "OAuth is not active; no public transport is enabled here".to_string()
    };
    loop {
        terminal.draw(|f| render_panel(f, &pending, selected, &status, oauth.is_some()))?;
        if !event::poll(POLL)? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(()),
            KeyCode::Up => selected = selected.saturating_sub(1),
            KeyCode::Down => selected = (selected + 1).min(pending.len().saturating_sub(1)),
            KeyCode::Char('r') | KeyCode::Char('R') => status = "Request list refreshed".into(),
            KeyCode::Char('d') | KeyCode::Char('D') if oauth.is_some() && !pending.is_empty() => {
                if confirm(terminal, "Deny this one request?").await? {
                    let denied = oauth
                        .unwrap()
                        .deny_locally(&pending[selected].request_id)
                        .await;
                    status = if denied {
                        "Request denied locally".into()
                    } else {
                        "No longer pending".into()
                    };
                }
            }
            KeyCode::Char('a') | KeyCode::Char('A') if oauth.is_some() && !pending.is_empty() => {
                if confirm(
                    terminal,
                    "Approve READ-ONLY access for this displayed client/resource?",
                )
                .await?
                {
                    if let Some(mut secret) = read_secret_locally(terminal).await? {
                        let result = oauth
                            .unwrap()
                            .approve_locally(&pending[selected].request_id, &secret)
                            .await;
                        secret.zeroize();
                        status = if result.is_ok() {
                            "Approved locally; browser can complete the one-time code".into()
                        } else {
                            "Approval rejected: incorrect key, expired request or rate limit".into()
                        };
                    }
                }
            }
            KeyCode::Char('x') | KeyCode::Char('X') if oauth.is_some() => {
                if confirm(
                    terminal,
                    "EMERGENCY: revoke every OAuth token, code and pending request?",
                )
                .await?
                {
                    if let Some(mut secret) = read_secret_locally(terminal).await? {
                        let result = oauth.unwrap().revoke_all_locally(&secret).await;
                        secret.zeroize();
                        status = if result.is_ok() {
                            "All OAuth grants and pending requests revoked".into()
                        } else {
                            "Emergency revocation refused: invalid owner key".into()
                        };
                    }
                }
            }
            _ => {}
        }
        if let Some(oauth) = oauth {
            pending = oauth.pending_requests_locally().await;
            selected = selected.min(pending.len().saturating_sub(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn inactive_screen_never_claims_oauth_is_enabled() {
        let mut term = Terminal::new(TestBackend::new(90, 16)).unwrap();
        term.draw(|f| render_panel(f, &[], 0, "Disabled", false))
            .unwrap();
        let buffer = term.backend().buffer();
        let content = (0..16)
            .flat_map(|r| (0..90).map(move |c| (c, r)))
            .map(|(c, r)| buffer[(c, r)].symbol().to_string())
            .collect::<String>();
        assert!(content.contains("INACTIVE"));
        assert!(content.contains("Funnel remains disabled"));
        assert!(!content.contains("owner_key"));
    }

    #[test]
    fn approval_screen_renders_public_metadata_not_secrets() {
        let items = vec![PendingApproval {
            request_id: "random-request-id".into(),
            client_id: "https://chatgpt.com/oauth/client.json".into(),
            resource: "https://private.example/s/mcp".into(),
            scope: "catdesk:read".into(),
        }];
        let text = panel_lines(&items, 0, "Ready", true)
            .iter()
            .map(|l| format!("{l:?}"))
            .collect::<String>();
        assert!(text.contains("random-request-id"));
        assert!(text.contains("catdesk:read"));
        assert!(!text.contains("owner_key"));
        assert!(!text.contains("access_token"));
    }
}
