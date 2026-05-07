#!/bin/bash
# ~/.seth → ~/.fetih geçiş betiği (tek seferlik)
SETH_DIR="$HOME/.seth"
FETIH_DIR="$HOME/.fetih"

if [ -d "$SETH_DIR" ] && [ ! -d "$FETIH_DIR" ]; then
  cp -r "$SETH_DIR" "$FETIH_DIR"
  echo "Geçiş tamamlandı: $SETH_DIR → $FETIH_DIR"
elif [ -d "$FETIH_DIR" ]; then
  : # zaten geçirilmiş
fi
