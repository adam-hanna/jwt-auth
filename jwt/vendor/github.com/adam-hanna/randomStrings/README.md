# Random Strings in GoLang
This simple library creates random strings on N length

Thanks to @elithrar for the code!
Source: https://elithrar.github.io/article/generating-secure-random-numbers-crypto-rand/

## Usage

```
import "github.com/adam-hanna/randomstrings"

sRand, err := randomstrings.GenerateRandomString(16) // generates a 16 digit random string
if err != nil {
	// panic!
}
log.Println(sRand)
```