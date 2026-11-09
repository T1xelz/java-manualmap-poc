package org.t1xel;

import java.util.ArrayList;
import java.util.List;

/**
 * Byte-pattern scanner with single-byte and variable-width wildcards.
 * Port of the Pattern.h matcher used by Simple-Manual-Map-Injector, kept
 * allocation-free per candidate so remote section buffers can be scanned
 * without a native helper.
 */
final class PatternScanner {
    private PatternScanner() {
    }

    private sealed interface Token permits ByteToken, RangeToken {
    }

    private record ByteToken(int value, boolean wildcard) implements Token {
    }

    private record RangeToken(int min, int max) implements Token {
    }

    static List<Token> compile(String pattern) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < pattern.length()) {
            char c = pattern.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
                continue;
            }
            if (tokens.size() >= 512) {
                throw new IllegalArgumentException("Pattern has too many tokens");
            }
            if (c == '?') {
                tokens.add(new ByteToken(0, true));
                i += i + 1 < pattern.length() && pattern.charAt(i + 1) == '?' ? 2 : 1;
                continue;
            }
            if (c == '[') {
                int close = pattern.indexOf(']', i + 1);
                int dash = pattern.indexOf('-', i + 1);
                if (close < 0 || dash < 0 || dash > close) {
                    throw new IllegalArgumentException("Malformed variable-width wildcard");
                }
                int min = Integer.parseInt(pattern.substring(i + 1, dash).trim());
                int max = Integer.parseInt(pattern.substring(dash + 1, close).trim());
                if (min < 0 || max < min) {
                    throw new IllegalArgumentException("Invalid variable-width wildcard range");
                }
                tokens.add(new RangeToken(min, max));
                i = close + 1;
                continue;
            }
            if (i + 1 < pattern.length() && hex(c) >= 0 && hex(pattern.charAt(i + 1)) >= 0) {
                tokens.add(new ByteToken(hex(c) << 4 | hex(pattern.charAt(i + 1)), false));
                i += 2;
                continue;
            }
            throw new IllegalArgumentException("Invalid pattern character at " + i);
        }
        if (tokens.isEmpty()) {
            throw new IllegalArgumentException("Empty pattern");
        }
        return List.copyOf(tokens);
    }

    static int scan(byte[] data, int offset, int length, String pattern, int skip) {
        List<Token> tokens = compile(pattern);
        int minimum = minimumLength(tokens);
        if (minimum == 0 || minimum > length) {
            return -1;
        }
        for (int i = 0; i <= length - minimum; i++) {
            if (matchAt(data, offset + i, length - i, tokens, 0)) {
                if (skip == 0) {
                    return offset + i;
                }
                skip--;
            }
        }
        return -1;
    }

    static int scanBackward(byte[] data, int offset, int length, String pattern) {
        List<Token> tokens = compile(pattern);
        int minimum = minimumLength(tokens);
        if (minimum == 0 || minimum > length) {
            return -1;
        }
        for (int i = length - minimum; i >= 0; i--) {
            if (matchAt(data, offset + i, length - i, tokens, 0)) {
                return offset + i;
            }
        }
        return -1;
    }

    private static boolean matchAt(byte[] data, int offset, int length, List<Token> tokens, int token) {
        while (token < tokens.size()) {
            Token current = tokens.get(token);
            if (current instanceof RangeToken range) {
                for (int skip = range.min(); skip <= range.max(); skip++) {
                    if (skip > length) {
                        break;
                    }
                    if (matchAt(data, offset + skip, length - skip, tokens, token + 1)) {
                        return true;
                    }
                }
                return false;
            }
            ByteToken single = (ByteToken) current;
            if (length == 0) {
                return false;
            }
            if (!single.wildcard() && (data[offset] & 255) != single.value()) {
                return false;
            }
            offset++;
            length--;
            token++;
        }
        return true;
    }

    private static int minimumLength(List<Token> tokens) {
        int minimum = 0;
        for (Token token : tokens) {
            minimum += token instanceof RangeToken range ? range.min() : 1;
        }
        return minimum;
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        return -1;
    }
}
