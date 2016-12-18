FROM openthings/ubuntu-golang:ARM64

ENV GIT_SSL_NO_VERIFY=true
ENV GO17VENDOREXPERIMENT 1

RUN apt-get update && apt-get install -y libpcap-dev python-requests time file
#RUN go get github.com/golang/lint/golint github.com/fzipp/gocyclo github.com/client9/misspell/cmd/misspell

RUN  git clone --progress https://github.com/golang/lint \
	"$GOPATH/src/github.com/golang/lint" &&\
     git clone --progress https://github.com/fzipp/gocyclo \
	"$GOPATH/src/github.com/fzipp/gocyclo" &&\
     git clone --progress https://github.com/client9/misspell \
	"$GOPATH/src/github.com/client9/misspell"

RUN go clean -i net && go install -tags netgo std
#RUN go install -race -tags netgo std

COPY build.sh /
ENTRYPOINT ["sh", "/build.sh"]
