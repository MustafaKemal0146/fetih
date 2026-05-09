#!/bin/bash
# ~/.seth → ~/.fetih geçiş betiği (tek seferlik)
FETIH_DIR="$HOME/.seth"
FETIH_DIR="$HOME/.fetih"

if [ -d "$FETIH_DIR" ] && [ ! -d "$FETIH_DIR" ]; then
  cp -r "$FETIH_DIR" "$FETIH_DIR"
  echo "Geçiş tamamlandı: $FETIH_DIR → $FETIH_DIR"
elif [ -d "$FETIH_DIR" ]; then
  : # zaten geçirilmiş
fi
