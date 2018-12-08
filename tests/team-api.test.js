const path = require('path')
const test = require('ava')

const db = require('../db')
const server = require('../index')()

const migrationsDirectory = path.join(__dirname, '..', 'db', 'migrations')

test.before(async () => {
  await db.migrate.latest({ directory: migrationsDirectory })
})

test.after.always(async () => {
  await db.migrate.rollback({ directory: migrationsDirectory })
  db.destroy()
  server.close()
})

function getTeam (id, callback) {
  server.inject({
    method: 'GET',
    url: `/api/teams/${id}`
  }, callback)
}

function getTeamList (callback) {
  server.inject({
    method: 'GET',
    url: '/api/teams'
  }, callback)
}

function createTeam (body, callback) {
  server.inject({
    method: 'POST',
    url: '/api/teams',
    payload: body
  }, callback)
}

function updateTeam (id, body, callback) {
  server.inject({
    method: 'PUT',
    url: `/api/teams/${id}`,
    payload: body
  }, callback)
}

function destroyTeam (id, callback) {
  server.inject({
    method: 'DELETE',
    url: `/api/teams/${id}`
  }, callback)
}

function addMember (id, osmId, callback) {
  server.inject({
    method: 'PUT',
    url: `/api/teams/add/${id}/${osmId}`
  }, callback)
}

function updateMembers (id, body, callback) {
  server.inject({
    method: 'PATCH',
    url: `/api/teams/${id}/members`,
    payload: body
  }, callback)
}

function removeMember (id, osmId, callback) {
  server.inject({
    method: 'PUT',
    url: `/api/teams/remove/${id}/${osmId}`
  }, callback)
}

test.cb('create a team', (t) => {
  createTeam({ name: 'road team 1' }, (err, response) => {
    t.falsy(err)
    const { payload, headers, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)
    t.true(headers['content-type'] === 'application/json; charset=utf-8')
    t.true(data.name === 'road team 1')
    t.end()
  })
})

test.cb('update a team', (t) => {
  createTeam({ name: 'map team 1' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)
    t.true(data.name === 'map team 1')

    updateTeam(data.id, { name: 'poi team 1' }, (err, response) => {
      t.falsy(err)
      const { payload, statusCode } = response
      const updated = JSON.parse(payload)
      t.true(statusCode === 200)
      t.true(updated.name === 'poi team 1')
      t.end()
    })
  })
})

test.cb('destroy a team', (t) => {
  createTeam({ name: 'map team 2' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)
    t.true(data.name === 'map team 2')

    destroyTeam(data.id, (err, response) => {
      t.falsy(err)
      t.true(response.statusCode === 200)
      t.end()
    })
  })
})

test.cb('get a team', (t) => {
  createTeam({ name: 'map team 3' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)

    getTeam(data.id, (err, response) => {
      t.falsy(err)
      const { payload, headers, statusCode } = response
      const retrieved = JSON.parse(payload)
      t.true(statusCode === 200)
      t.true(headers['content-type'] === 'application/json; charset=utf-8')
      t.true(retrieved.id === data.id)
      t.end()
    })
  })
})

test.cb('get team list', (t) => {
  createTeam({ name: 'map team 4' }, (err, response) => {
    t.falsy(err)
    t.true(response.statusCode === 200)

    getTeamList((err, response) => {
      t.falsy(err)
      const { payload, headers, statusCode } = response
      const data = JSON.parse(payload)
      t.true(statusCode === 200)
      t.true(headers['content-type'] === 'application/json; charset=utf-8')
      t.true(data.length > 0)
      data.forEach((item) => {
        t.truthy(item.name)
        t.truthy(item.id)
      })
      t.end()
    })
  })
})

test.cb('add member to team', t => {
  createTeam({ name: 'map team 24' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)

    addMember(data.id, 1, (err) => {
      t.falsy(err)
      getTeam(data.id, (err, response) => {
        t.falsy(err)
        const { payload, headers, statusCode } = response
        const retrieved = JSON.parse(payload)
        t.true(statusCode === 200)
        t.true(headers['content-type'] === 'application/json; charset=utf-8')
        t.true(retrieved.id === data.id)
        t.true(retrieved.members.length === 1)
        t.true(retrieved.members[0] === '1')
        t.end()
      })
    })
  })
})

test.cb('remove member to team', t => {
  createTeam({ name: 'map team 25' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)

    addMember(data.id, 1, (err) => {
      t.falsy(err)
      removeMember(data.id, 1, (err) => {
        t.falsy(err)
        getTeam(data.id, (err, response) => {
          t.falsy(err)
          const { payload, headers, statusCode } = response
          const retrieved = JSON.parse(payload)
          t.true(statusCode === 200)
          t.true(headers['content-type'] === 'application/json; charset=utf-8')
          t.true(retrieved.id === data.id)
          t.true(retrieved.members.length === 0)
          t.end()
        })
      })
    })
  })
})

test.cb('update members to team', t => {
  createTeam({ name: 'map team 26' }, (err, response) => {
    t.falsy(err)
    const { payload, statusCode } = response
    const data = JSON.parse(payload)
    t.true(statusCode === 200)

    updateMembers(data.id, { add: ['1', '2', '3'] }, (err) => {
      t.falsy(err)
      getTeam(data.id, (err, response) => {
        t.falsy(err)
        const { payload, headers, statusCode } = response
        const retrieved = JSON.parse(payload)
        t.true(statusCode === 200)
        t.true(headers['content-type'] === 'application/json; charset=utf-8')
        t.true(retrieved.id === data.id)
        t.true(retrieved.members.length === 3)
        t.end()
      })
    })
  })
})
