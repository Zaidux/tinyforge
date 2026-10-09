# What's this, in plain words

A version of this project with no jargon. If you read only one file, read
this one.

## The short version

Most AI chatbots are enormous — they need a warehouse of computer chips to
run. We're building a **tiny** one that fits on this little box, and giving
it a job that tiny things are actually good at.

## 1. Why not just build a small chatbot?

Because small chatbots are bad at it. We checked: the smallest good-enough
chatbot you can download scores **1.4 out of 100** on a basic maths test.
One. That is not a chatbot, that's a guessing machine with a nice voice.

We also tried doing the maths on whether we could train one from scratch
here. Answer: **about five years.** This box has one computer chip in it.

So: we are not building a small chatbot. We are building a small
**checker**.

## 2. What does the checker do?

Imagine sending a security researcher into a building to look for unlocked
doors.

They're good. They check 12 doors. But there are 40 doors, and they never
tried the ones on the third floor. They write a report saying "I found
three unlocked doors" — and they don't mention that they never went upstairs.

**That gap — the doors they never tried — is what we detect.**

The big AI writes the report. Our tiny program looks over its shoulder and
asks: *"what did you not do?"*

## 3. Why is a tiny program good at this?

This is the surprising part, and it's the whole idea.

Asking "what didn't they try?" is not a hard-thinking question. It's a
**counting** question. Did they test for SQL injection? Check the list:
yes. Path traversal? No. Say so.

Counting is easy. Thinking is hard. So we give the hard thinking to the big
smart chatbot and the easy counting to our tiny program.

There's another reason, and it's about trust. The big chatbot wrote the
report. Ask it "what did you miss?" and it says "nothing, I'm great." We
measured this: on tests where the AI got the job **wrong**, it claimed
success **90% of the time**.

A separate tiny program has nothing to gain from lying. That's the point.

## 4. What does "paired" mean?

Our tiny program never works alone. It sits under a big AI:

```
        ┌──────────────────────┐
        │   Big AI (smart)     │  writes the report, does the thinking
        └──────────┬───────────┘
                   │
        ┌──────────▼───────────┐
        │ Tiny program (dumb)  │  "you never checked X"
        └──────────────────────┘
```

If the report gets better when the tiny program is switched on, the tiny
program earned its place. That's the whole experiment.

## 5. Why we test so hard before trusting it

Our first checker scored **zero**. Not bad — zero. We'd built it to look at
which tools were used, but we'd never told it what tools exist.

Then we fixed it and it scored **perfect**. And we didn't believe that,
because it was checking its own homework: we'd written both the checker and
the answer key.

So we went and got **someone else's** answer key — a public benchmark
written by strangers — and tested again. It passed, but only on 7 of our 23
categories. Fetching that real data also exposed a **real bug**: our checker
had no idea how to notice remote code execution, which is the single most
common kind of security hole. On any modern target it would have cried wolf
every single time.

**Real data found a bug that our own data never could.** That's why we went
to the trouble.

## 6. Three things that are easy to get wrong

**Being too eager to say "you missed something."**
Think of a smoke alarm that goes off every 5 minutes. Eventually you turn
it off — and then it misses the actual fire. A checker that flags
everything is worse than no checker. So ours is built to stay quiet unless
it's confident.

**Measuring something too small to see.**
If you test 200 times and the answer moves by 2%, you cannot tell real change
from random noise. We did the maths: to reliably spot a 3% improvement you
need about **3,500 tests**. Most small experiments don't do that, and they
report luck as a win.

**Getting stuck thinking and saying nothing.**
Our AI once used up its entire word budget thinking about a question and
returned literally nothing. We'd have recorded that as "the AI failed" — but
it hadn't failed, it had run out of room. We added a check for that
specifically, because otherwise it quietly ruins every test.

## 7. Where the project is right now

Done: the checker, the testing kit, the honest measurements, and the bug fix.

Not done: we haven't built the tiny checker's brain yet, and we haven't
generated its training examples.

The next real question we're chasing: **can we make a checker good enough
that turning it on makes a big AI measurably better?** Your original goal —
about 10% — is plausible for "did it miss something." It is *not* plausible
for "is the reasoning smarter," and it's probably **negative** for
"is it more creative," because a checker that rewards safe answers will
quietly stop the AI from trying anything unusual.

Being clear about which of those works is worth more than a big number.

## Words we use

| Plain words | What the computer people call it |
|---|---|
| Checker | scorer / blind-spot detector |
| Doors it never tried | blind spots / coverage gaps |
| Made something up without checking | hallucination / ungrounded claim |
| The list of doors that should have been checked | taxonomy |
| Real bug that made it cry wolf | false positive |
| Staying quiet when unsure | abstention |
| Answer key written by strangers | third-party ground truth |
| The box with one chip in it | the dev host |
| Small program that counts | the student model |