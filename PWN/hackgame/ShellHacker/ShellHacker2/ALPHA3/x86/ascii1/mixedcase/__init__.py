import rm32
import i32
import getpc

encoders = rm32.encoders + i32.encoders + getpc.encoders
# encoders.extend(ascii_art.encoders)
for encoder in encoders:
    encoder["case"] = "mixedcase"
