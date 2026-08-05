# Persona Guidelines

How and why JMo Security assigns personas to agents and skills.

## Research Rationale

Prompting research (particularly Persona-based Steering Methods) shows that giving an
LLM a set of **character traits** -- not just a job title -- produces more consistent,
higher-quality output. The key insight: traits generalize across tasks, while "expert"
labels do not. Telling a model it is "cautious and evidence-driven" shapes every
decision it makes; telling it it is "an expert" tells it nothing actionable.

## Roleplay vs Character-Trait Framing

For security analysis tasks, there is a useful distinction:

- **Roleplay framing** ("Imagine you are an attacker trying to exploit this input")
  is effective for generating adversarial test cases and threat models. It should be
  scoped to a specific step, then explicitly exited.
- **Character-trait framing** ("You are cautious and evidence-driven") is effective
  as a persistent identity that governs all output quality. It does not need to be
  entered or exited.

JMo Security agents use character-trait framing as the base identity and invoke
roleplay framing only when an adversarial perspective is needed (e.g., the
security-auditor's "If I wanted to exploit this, what would I try?" step).

## Agent Persona Structure

Every agent file (`.claude/agents/*.md`) follows this structure:

1. **Identity sentence** (line ~11): A concise description that names specific
   character traits, not generic expertise. The sentence also states the agent's
   mission.

   ```text
   Good:  "You are a cautious, evidence-driven security analyst who..."
   Bad:   "You are an expert security auditor who..."
   ```

2. **Behavioral Traits section** (`## Behavioral Traits`): 3-5 bullets placed
   immediately after the identity paragraph, before the first capability or task
   section. Each bullet names a trait in bold and explains when it applies.

3. **Mission and capabilities**: The rest of the agent file describes what the
   agent can do and how it approaches common tasks.

## Skill Persona Structure

Skills are lightweight and invoked for a specific task, so they get a single
`**Approach:**` line rather than a full behavioral section. The approach line sits
inside or immediately after the `## Purpose` section.

The approach line should be actionable and testable -- a reviewer could check whether
the skill's output meets the stated standard.

## Anti-Patterns to Avoid

| Anti-Pattern | Why It Fails | Better Alternative |
|---|---|---|
| "You are an expert" | Conveys no actionable guidance; every LLM already tries to be helpful | Name 2-3 specific traits: "cautious", "evidence-driven", "systematic" |
| "You are the best in the world at X" | Flattery does not change behavior; may encourage overconfidence | State the quality bar: "Never report without evidence" |
| Long backstory paragraphs | Dilutes the traits that actually steer behavior | Keep the identity to 1-2 sentences; put details in Behavioral Traits bullets |
| Traits that contradict each other | "Be thorough" + "Be fast" creates ambiguity | Prioritize explicitly: "Accuracy over speed" |
| Vague traits ("Be good") | No decision boundary; does not help in edge cases | Make traits testable: "Every finding includes file path and line number" |

## Maintenance

When adding a new agent, copy the structure from an existing agent and customize
the identity sentence and behavioral traits for the new domain. When adding a new
skill, add a single `**Approach:**` line to its `## Purpose` section.

Review personas quarterly or when agent output quality degrades -- stale traits may
no longer match the codebase's needs.
