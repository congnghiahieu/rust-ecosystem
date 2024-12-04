package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

type JSONModel struct {
	CveID        string `json:"cve_id"`
	RepoURL      string `json:"repo_url"`
	Parents      string `json:"parents"`
	Hash         string `json:"hash"`
	ParentURL    string `json:"parent_url"`
	CommitURL    string `json:"commit_url"`
	FileChangeID string `json:"file_change_id"`
	PathChange   bool   `json:"path_change"`
	OldPath      string `json:"old_path"`
	NewPath      string `json:"new_path"`
	OldURL       string `json:"old_url"`
	NewURL       string `json:"new_url"`
	RawOldURL    string `json:"raw_old_url"`
	RawNewURL    string `json:"raw_new_url"`
}

func loadJSONModel(filePath string) ([]JSONModel, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var models []JSONModel
	err = json.NewDecoder(file).Decode(&models)
	if err != nil {
		return nil, err
	}

	return models, nil
}

func downloadFile(model JSONModel, wg *sync.WaitGroup) {
	defer wg.Done()

	resp, err := http.Get(model.RawOldURL)
	if err != nil {
		fmt.Println("Error downloading:", model.RawOldURL, err)
		return
	}
	defer resp.Body.Close()

	folderPath := "downloads.go"
	if err := os.MkdirAll(folderPath, fs.ModePerm); err != nil {
		fmt.Println("Error creating folder:", folderPath, err)
		return
	}

	fileName := filepath.Join(folderPath, model.Parents + ".rs")
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", fileName, err)
		return
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		fmt.Println("Error saving file:", fileName, err)
		return
	}

	fmt.Println("Downloaded:", fileName)
}

func main() {
	var wg sync.WaitGroup

	models, err := loadJSONModel("merge.json")
	if err != nil {
		fmt.Println("Error loading JSON model:", err)
		return
	}

	for _, model := range models {
		wg.Add(1)
		go downloadFile(model, &wg)
	}

	wg.Wait()
}