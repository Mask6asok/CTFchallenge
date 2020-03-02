import mixedcase
import lowercase
import uppercase

encoders = mixedcase.encoders + lowercase.encoders + uppercase.encoders
for encoder in encoders:
    encoder["character encoding"] = "ascii"
