use std::collections::HashMap;
use std::error::Error;
use std::io;

use capstone::Capstone;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::{
    CollectEntry, CollectNote, DisasmCfg, DisasmLine, PatternMatch, XRegion, collect_disass,
};

struct App {
    matches: Vec<PatternMatch>,
    regions: Vec<XRegion>,
    cs: Capstone,
    cfg: DisasmCfg,
    list_state: ListState,
    scroll: u16,
    cache: HashMap<usize, Rendered>,
    last_pane_height: u16,
    focus_disasm: bool,
}

struct Rendered {
    lines: Vec<DisasmLine>,
    notes: Vec<CollectEntry>,
}

impl App {
    fn ensure_cached(&mut self, idx: usize) {
        if !self.cache.contains_key(&idx) {
            let mut lines = Vec::new();
            let mut notes = Vec::new();
            collect_disass(
                &self.cs,
                &self.regions,
                &self.cfg,
                self.matches[idx].vaddr,
                0,
                &mut lines,
                &mut notes,
            );
            self.cache.insert(idx, Rendered { lines, notes });
        }
    }

    fn current_total_rows(&self) -> u16 {
        let idx = match self.list_state.selected() {
            Some(i) => i,
            None => return 0,
        };
        self.cache
            .get(&idx)
            .map(|r| (r.lines.len() + r.notes.len()) as u16)
            .unwrap_or(0)
    }

    fn clamp_scroll(&mut self) {
        let total = self.current_total_rows();
        let visible = self.last_pane_height.saturating_sub(2);
        let max = total.saturating_sub(visible);
        if self.scroll > max {
            self.scroll = max;
        }
    }

    fn render(&mut self, frame: &mut Frame) {
        let outer = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]);
        let [body, status] = frame.area().layout::<2>(&outer);

        let inner = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)]);
        let [left, right] = body.layout::<2>(&inner);

        self.last_pane_height = right.height;

        let items: Vec<ListItem> = self
            .matches
            .iter()
            .enumerate()
            .map(|(i, m)| ListItem::new(format!("#{} 0x{:x}", i + 1, m.vaddr)))
            .collect();
        let list_block = Block::default()
            .title(format!(" matches ({}) ", self.matches.len()))
            .borders(Borders::ALL)
            .border_style(if !self.focus_disasm {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            });
        let list = List::new(items)
            .block(list_block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol("> ");
        frame.render_stateful_widget(list, left, &mut self.list_state);

        let selected = self.list_state.selected();
        if let Some(idx) = selected {
            self.ensure_cached(idx);
            self.clamp_scroll();
            let r = self.cache.get(&idx).unwrap();
            let mut text_lines: Vec<Line> = r
                .lines
                .iter()
                .map(|line| render_disasm_line(line))
                .collect();
            for n in &r.notes {
                text_lines.push(render_note_line(n));
            }
            let m = &self.matches[idx];
            let title = format!(
                " #{}/{}  Offset: 0x{:x}  Vaddr: 0x{:x} ",
                idx + 1,
                self.matches.len(),
                m.file_offset,
                m.vaddr
            );
            let para_block = Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(if self.focus_disasm {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });
            let para = Paragraph::new(Text::from(text_lines))
                .block(para_block)
                .scroll((self.scroll, 0));
            frame.render_widget(para, right);
        } else {
            let para = Paragraph::new("no matches")
                .block(Block::default().title(" disassembly ").borders(Borders::ALL));
            frame.render_widget(para, right);
        }

        let hint = Line::from(vec![
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" focus  "),
            Span::styled("PgUp/PgDn/Space", Style::default().fg(Color::Yellow)),
            Span::raw(" scroll  "),
            Span::styled("Home/End", Style::default().fg(Color::Yellow)),
            Span::raw(" top/bot  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit"),
        ]);
        frame.render_widget(Paragraph::new(hint), status);
    }
}

fn render_disasm_line(line: &DisasmLine) -> Line<'static> {
    let pad = "    ".repeat(line.indent);
    let prefix = if line.is_branch_start {
        let outer = if line.indent > 0 {
            "    ".repeat(line.indent - 1)
        } else {
            String::new()
        };
        format!("{}└-->", outer)
    } else {
        pad
    };
    Line::from(vec![
        Span::raw(prefix),
        Span::styled(
            format!("0x{:016x}: ", line.address),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(line.asm.clone(), Style::default().fg(Color::Blue)),
    ])
}

fn render_note_line(n: &CollectEntry) -> Line<'static> {
    let pad = "    ".repeat(n.indent);
    let msg = match n.note {
        CollectNote::InvalidAddress(v) => format!("{}invalid address 0x{:x}", pad, v),
        CollectNote::DecodeFailed(v) => format!("{}decode failed at 0x{:x}", pad, v),
    };
    Line::from(Span::styled(msg, Style::default().fg(Color::Yellow)))
}

pub fn run(
    matches: Vec<PatternMatch>,
    regions: Vec<XRegion>,
    cs: Capstone,
    cfg: DisasmCfg,
) -> Result<(), Box<dyn Error>> {
    let mut app = App {
        matches,
        regions,
        cs,
        cfg,
        list_state: ListState::default(),
        scroll: 0,
        cache: HashMap::new(),
        last_pane_height: 0,
        focus_disasm: false,
    };
    if !app.matches.is_empty() {
        app.list_state.select(Some(0));
    }

    let result: io::Result<()> = ratatui::run(|terminal| {
        loop {
            terminal.draw(|frame| app.render(frame))?;
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let scroll_step = app.last_pane_height.saturating_sub(2).max(1);
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                        KeyCode::Tab => app.focus_disasm = !app.focus_disasm,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.focus_disasm {
                                app.scroll = app.scroll.saturating_sub(1);
                            } else {
                                app.list_state.select_previous();
                                app.scroll = 0;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.focus_disasm {
                                app.scroll = app.scroll.saturating_add(1);
                            } else {
                                app.list_state.select_next();
                                app.scroll = 0;
                            }
                        }
                        KeyCode::PageUp => {
                            app.scroll = app.scroll.saturating_sub(scroll_step);
                        }
                        KeyCode::PageDown | KeyCode::Char(' ') => {
                            app.scroll = app.scroll.saturating_add(scroll_step);
                        }
                        KeyCode::Home => {
                            if app.focus_disasm {
                                app.scroll = 0;
                            } else {
                                app.list_state.select_first();
                                app.scroll = 0;
                            }
                        }
                        KeyCode::End => {
                            if app.focus_disasm {
                                app.scroll = u16::MAX;
                            } else {
                                app.list_state.select_last();
                                app.scroll = 0;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    });

    result.map_err(|e| Box::new(e) as Box<dyn Error>)?;
    Ok(())
}
