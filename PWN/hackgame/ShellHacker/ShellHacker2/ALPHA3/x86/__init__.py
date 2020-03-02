import ascii1
import latin_1
import utf_16

encoders = ascii.encoders + latin_1.encoders + utf_16.encoders
for encoder in encoders:
    encoder["architecture"] = "x86"
