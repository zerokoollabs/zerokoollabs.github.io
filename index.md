---
layout: default
title: Zerokoollabs
---

# Zerokoollabs

Welcome to my blog. Here's what I've been working on:

<ul>
  {% for post in site.posts %}
    <li>
      <a href="{{ post.url }}">{{ post.title }}</a> — <small>{{ post.date | date: "%B %d, %Y" }}</small>
    </li>
  {% endfor %}
</ul>
