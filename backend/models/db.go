package models

import "os"

func ensureDataFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(`{"next_id":1,"users":[]}`))
	return err
}
