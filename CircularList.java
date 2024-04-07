package boil_detection_project;

import java.util.*;

class CircularList<T> {
    private List<T> items;
    private int currentIndex;

    public CircularList(List<T> initialList) {
        if (initialList.isEmpty()) {
            throw new IllegalArgumentException("Initial list must not be empty");
        }
        items = new ArrayList<>(initialList);
        currentIndex = 0;
    }

    public T next() {
        if (items.isEmpty()) {
            throw new NoSuchElementException("List is empty");
        }

        currentIndex = (currentIndex + 1) % items.size();
        return items.get(currentIndex);
    }

    public T previous() {
        if (items.isEmpty()) {
            throw new NoSuchElementException("List is empty");
        }

        currentIndex = (currentIndex - 1 + items.size()) % items.size();
        return items.get(currentIndex);
    }

    public T getCurrent() {
        if (items.isEmpty()) {
            throw new NoSuchElementException("List is empty");
        }

        return items.get(currentIndex);
    }
}