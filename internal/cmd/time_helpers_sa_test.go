package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

// newCalendarServicePrimaryNotFound creates a calendar service whose
// CalendarList.Get("primary") endpoint returns 404, simulating pure
// service-account mode where no primary calendar exists.
func newCalendarServicePrimaryNotFound(t *testing.T) *calendar.Service {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All calendarList requests return 404.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Not Found","errors":[{"message":"Not Found","domain":"global","reason":"notFound"}]}}`))
	}))
	t.Cleanup(srv.Close)

	svc, err := calendar.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithHTTPClient(srv.Client()),
		option.WithEndpoint(srv.URL+"/"),
	)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestGetUserTimezone_PrimaryNotFound_FallsBackToUTC(t *testing.T) {
	svc := newCalendarServicePrimaryNotFound(t)

	loc, err := getUserTimezone(context.Background(), svc)
	if err != nil {
		t.Fatalf("getUserTimezone returned error: %v", err)
	}
	if loc != time.UTC {
		t.Fatalf("expected UTC fallback, got %v", loc)
	}
}

func TestResolveTimeRange_PrimaryNotFound_Succeeds(t *testing.T) {
	svc := newCalendarServicePrimaryNotFound(t)

	tr, err := ResolveTimeRange(context.Background(), svc, TimeRangeFlags{})
	if err != nil {
		t.Fatalf("ResolveTimeRange returned error: %v", err)
	}
	if tr.Location != time.UTC {
		t.Fatalf("expected UTC location, got %v", tr.Location)
	}
	if tr.From.IsZero() || tr.To.IsZero() {
		t.Fatal("expected non-zero time range")
	}
}
