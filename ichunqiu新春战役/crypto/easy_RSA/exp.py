import gmpy2
from Crypto.Util.number import long_to_bytes
n = 7772032347449135823378220332275440993540311268448333999104955932478564127911903406653058819764738253486720397879672764388694000771405819957057863950453851364451924517697547937666368408217911472655460552229194417053614032700684618244535892388408163789233729235322427060659037127722296126914934811062890693445333579231298411670177246830067908917781430587062195304269374876255855264856219488896495236456732142288991759222315207358866038667591630902141900715954462530027896528684147458995266239039054895859149945968620353933341415087063996651037681752709224486183823035542105003329794626718013206267196812545606103321821
c = 2082303370386500999739407038433364384531268495285382462393864784029350314174833975697290115374382446746560936195242108283558410023998631974392437760920681553607338859157019178565294055755787756920003102506579335103169629546410439497570201554568266074421781047420687173530441469299976286281709526307661219925667082812294328343298836241624597491473793807687939912877432920934022304415340311930199467500833755390490763679081685821950332292303679223444816832000945972744492944044912168217765156110058474974887372388032286968936052010531850687361328326741707441938740295431353926037925950161386891437897990887861853097318
e = 65537
for x in range(1020, 1025):
    delta = pow(2 ** x - 65538, 2) - 4 * n
    if delta >= 0:
        print x
        p = ((2 ** x - 65538) + gmpy2.iroot(delta, 2)[0]) / 2
        q = n / p
        r = (p - 1) * (q - 1)
        d = gmpy2.invert(e, r)
        flag = long_to_bytes(pow(c, d, n))
        print flag

for x in range(1020, 1025):
    delta = pow(2 ** x - 65538, 2) - 4 * n
    if delta >= 0:
        r = n - (2 ** x - 65538) + 1
        d = gmpy2.invert(e, r)
        flag = long_to_bytes(pow(c, d, n))
        print flag
