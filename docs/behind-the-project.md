---
title: Behind the Project
layout: default
nav_order: 2
---

# Behind the Project

This project basically started when I realized that, even after 13–14 years of writing software, I didn't really have a long-lasting, sustainable project that felt truly mine. So I decided to build something I could slowly shape over time — adding features whenever I had free time or when something popped into my mind that might help in my day-to-day work.

Most of the capabilities are built around the problems I often run into while analyzing mobile apps. It uses Unix Domain Sockets instead of TCP, relies on memfd + shellcode instead of ptrace, and includes a bunch of other techniques designed to avoid common detection patterns. So even though it's nowhere near as large or broad as the big established tools, it's focused, practical, and tailored to the kinds of challenges I deal with regularly.

The biggest motivation behind building it was this: working with huge codebases like Frida can be challenging when you're trying to add or adjust very specific features. There's nothing wrong with those projects — they're incredibly powerful — but sometimes you just want something lightweight, minimal, and fully under your control.

Having a small system I understand from top to bottom makes experimenting, extending, and debugging so much easier. I can tweak anything I want, whenever I want.

Hopefully, over time, this project will grow with contributions from other developers and evolve into a broader, more capable mobile security framework. And honestly, the idea that someday — even if I stop working on it, or life takes me elsewhere — someone might still pick it up, build on it, and keep it alive… that's a pretty amazing feeling.

*There's a certain charm in crafting your own little world — a system built by hand, shaped by your own ideas and quirks. If this world becomes useful to others one day, then the whole effort was worth it.*
