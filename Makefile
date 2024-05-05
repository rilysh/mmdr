# BSD 2-Clause License - by rilysh

PROGRAM = mmdr
INCL 	= /usr/local/include/
LIBR	= /usr/local/lib/
LLIB	= -lzip

all:
	${CC} ${PROGRAM}.c -I${INCL} -L${LIBR} ${LLIB} -o ${PROGRAM}

clean:
	@rm ${PROGRAM}
