#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace fivem::lua {

enum class Tok {
    End,
    Space,        // whitespace between tokens
    LineComment,  // -- ... to end of line
    BlockComment, // --[==[ ... ]==]
    String,       // '...', "...", [==[ ... ]==]
    Number,
    Name,
    Symbol,
};

struct Token {
    Tok kind = Tok::End;
    size_t begin = 0;
    size_t end = 0;
    std::string text;  // Name/Symbol/Number: exact source text. Comments: without markers.
    bool multiline = false;  // String/BlockComment containing a newline
    bool closed = true;      // String/BlockComment whose terminator was actually found
};

// Splits Lua source into tokens. Long brackets ([[, [==[) are handled with their level,
// so a bracket inside a string can never be mistaken for a comment or an index.
// The concatenation of every token's source range reproduces the input exactly.
std::vector<Token> tokenize(const std::string& source);

bool isIdentifierStart(char c);
bool isIdentifierChar(char c);
bool isKeyword(const std::string& name);
bool isOpeningKeyword(const std::string& name);
bool isClosingKeyword(const std::string& name);

} // namespace fivem::lua