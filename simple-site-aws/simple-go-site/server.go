package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/joho/godotenv"
)

var templates = template.Must(template.ParseFiles("templates/index.html"))

// Image ...
type Image struct {
	Key []string
}

func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func getEnvVariable(key string) string {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Could not load .env file")
	}

	return os.Getenv(key)
}

func getImagesFromS3() []string {
	sess := session.Must(session.NewSession())

	// Creating S3 client
	svc := s3.New(sess)

	response, err := svc.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(getEnvVariable("AWS_BUCKET"))})

	if err != nil {
		fmt.Println(err)
	}

	var imageList []string
	for _, item := range response.Contents {
		imageList = append(imageList, "https://"+getEnvVariable("AWS_BUCKET")+".s3.amazonaws.com/"+*item.Key)
	}

	return imageList
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	imageRefs := getImagesFromS3()
	err := templates.ExecuteTemplate(w, "index.html", imageRefs)
	if err != nil {
		fmt.Println(err)
	}
}

func main() {

	// register handler functions
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css"))))
	http.HandleFunc("/", viewHandler)

	fmt.Println("Listening on port " + getEnvVariable("APP_PORT"))
	log.Fatal(http.ListenAndServe(":"+getEnvVariable("APP_PORT"), nil))
}
